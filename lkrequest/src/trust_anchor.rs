use crate::error::{Error, Result};
use lktls::trust_anchor::{TrustAnchorInfo, TrustAnchorObserver};

pub(crate) fn finish_recovery<T>(
    result: Result<T>,
    first: TrustAnchorInfo,
    observer: &TrustAnchorObserver,
) -> Result<T> {
    let mut info = observer.snapshot();
    info.recovered = result.is_ok();
    if let Err(error) = &result {
        if info.failure.is_none() {
            info.failure = Some(error.to_string());
        }
    }
    info.previous_attempt = Some(Box::new(first));
    crate::diagnostics::record_trust_anchor(info.clone());
    result.map_err(|error| Error::TrustAnchorRecovery {
        source: Box::new(error),
        info: Box::new(info),
    })
}

#[cfg(feature = "quic-h3")]
pub(crate) fn quic_handshake_error(
    error: quinn::ConnectionError,
    observer: &TrustAnchorObserver,
) -> Error {
    record_quic_close(&error, observer);
    Error::quic(crate::error::QuicPhase::Handshake, error.to_string())
}

#[cfg(feature = "quic-h3")]
pub(crate) fn quic_backend_error(
    error: lkquic::QuinnBackendError,
    observer: &TrustAnchorObserver,
) -> Error {
    if let lkquic::QuinnBackendError::Connection(connection) = &error {
        record_quic_close(connection, observer);
    }
    Error::quic(crate::error::QuicPhase::Handshake, error.to_string())
}

#[cfg(feature = "quic-h3")]
fn record_quic_close(error: &quinn::ConnectionError, observer: &TrustAnchorObserver) {
    let info = observer.snapshot();
    let peer_closed = match &error {
        quinn::ConnectionError::Reset | quinn::ConnectionError::ApplicationClosed(_) => true,
        quinn::ConnectionError::ConnectionClosed(close) => {
            matches!(u64::from(close.error_code), 0 | 0x128 | 0x130)
        }
        _ => false,
    };
    // A local TLS validation failure already has a precise classification.
    if peer_closed && info.failure.is_none() && !info.authenticated {
        observer.record_error(&lktls::error::TlsError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            error.to_string(),
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::execution::RequestExecution;
    use crate::timeout::RequestTimeout;

    #[tokio::test]
    async fn protocol_alternatives_share_one_request_budget() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let tcp_connection = execution.connection();
        let quic_connection = execution.connection();
        let (tcp, quic) = tokio::join!(async { tcp_connection.consume_tai_budget() }, async {
            quic_connection.consume_tai_budget()
        });
        assert_ne!(tcp, quic);
        let (independent, _independent_guard) = RequestExecution::new(RequestTimeout::default());
        assert!(independent.connection().consume_tai_budget());
    }

    #[tokio::test]
    async fn cancelled_and_concurrent_requests_keep_independent_budgets_and_hints() {
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocked = tokio::spawn(async move {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            assert!(execution.connection().consume_tai_budget());
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        blocked.abort();
        assert!(blocked.await.unwrap_err().is_cancelled());
        let requests: Vec<_> = (0..16)
            .map(|number| {
                tokio::spawn(async move {
                    let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
                    let observer = TrustAnchorObserver::default();
                    observer.update(|info| info.failure = Some(number.to_string()));
                    tokio::task::yield_now().await;
                    assert!(execution.connection().consume_tai_budget());
                    assert!(!execution.connection().consume_tai_budget());
                    assert_eq!(observer.snapshot().failure, Some(number.to_string()));
                })
            })
            .collect();
        for request in requests {
            request.await.unwrap();
        }
        let (independent, _independent_guard) = RequestExecution::new(RequestTimeout::default());
        assert!(independent.connection().consume_tai_budget());
    }
}
