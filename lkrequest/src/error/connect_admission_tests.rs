use std::cell::Cell;
use std::io;
use std::time::Duration;

use super::*;

fn h3_context(source: Error) -> Error {
    Error::H3RequestContext(Box::new(H3RequestContext {
        stage: H3ResponseStage::AwaitingResponse,
        kind: H3FailureKind::Other,
        backend_final_received: false,
        stopped_upload: None,
        connection_terminated: false,
        source: Box::new(source),
    }))
}

#[test]
fn typed_io_bridge_preserves_deadline_and_cancellation() {
    let deadline = Error::timeout("operation deadline", None, Some(Duration::from_secs(2)));
    let deadline = take_connect_execution_io(connect_execution_io(deadline)).unwrap();
    assert!(
        matches!(deadline, Error::Timeout { phase: None, duration: Some(duration), .. } if duration == Duration::from_secs(2))
    );
    assert!(!deadline.is_connect_attempt_denied());

    let (execution, guard) = crate::session::execution::ConnectionExecution::new();
    drop(guard);
    let cancellation = execution.commit_start("tcp").unwrap_err();
    let message = cancellation.to_string();
    let cancellation = take_connect_execution_io(connect_execution_io(cancellation)).unwrap();
    assert_eq!(cancellation.to_string(), message);
    assert!(matches!(cancellation, Error::Http(_)));
    assert!(!cancellation.is_retryable());
    assert!(!cancellation.is_connect_attempt_denied());

    let network = io::Error::new(io::ErrorKind::ConnectionRefused, "original network failure");
    let network = take_connect_execution_io(network).unwrap_err();
    assert_eq!(network.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(network.to_string(), "original network failure");
}

#[test]
fn typed_io_bridge_keeps_limit_and_original_failure() {
    let denial = Error::connect_attempt_denied(Some(3)).with_connect_prior(Error::Io(
        io::Error::new(io::ErrorKind::ConnectionReset, "original reset"),
    ));
    let denial = take_connect_execution_io(connect_execution_io(denial)).unwrap();
    assert!(matches!(&denial, Error::ConnectAttemptDenied(context) if context.limit() == Some(3)));
    let Error::Io(original) = denial.into_public_connect_error() else {
        panic!("original IO type must survive the bridge");
    };
    assert_eq!(original.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(original.to_string(), "original reset");
}

#[test]
fn first_prior_wins_and_raw_io_is_mapped_only_at_context_boundary() {
    let mapped = Cell::new(0);
    let denial = Error::connect_attempt_denied(Some(1))
        .with_connect_prior(Error::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "first failure",
        )))
        .with_connect_prior(Error::QuicHandshake("later failure".into()))
        .map_connect_prior(|prior| {
            mapped.set(mapped.get() + 1);
            match prior {
                Error::Io(source) => Error::proxy(
                    ProxyErrorKind::TcpConnectFailed,
                    format!("proxy TCP: {source}"),
                    Some(Box::new(source)),
                ),
                other => other,
            }
        });
    assert_eq!(mapped.get(), 1);
    assert!(denial.is_connect_attempt_denied());
    let original = denial.into_public_connect_error();
    assert_eq!(
        original.as_proxy_error().unwrap().kind,
        ProxyErrorKind::TcpConnectFailed
    );
    assert!(original.to_string().contains("first failure"));
    assert!(!original.to_string().contains("later failure"));

    let denial = Error::connect_attempt_denied(Some(0)).map_connect_prior(|_| {
        panic!("no original result exists to map");
    });
    assert!(matches!(
        denial.into_public_connect_error(),
        Error::ResourceLimitExceeded(_)
    ));
}

#[test]
fn refusal_does_not_inherit_retry_or_quarantine_classification_from_prior() {
    for prior in [
        Error::QuicHandshake("handshake timeout".into()),
        Error::proxy(ProxyErrorKind::TcpConnectFailed, "proxy unavailable", None),
        Error::connection_closed(
            ConnectionPhase::HttpRequest,
            ConnectionClosedKind::Reset,
            "reset",
        ),
        Error::timeout("late", Some(ConnectionPhase::QuicHandshake), None),
    ] {
        let denial = h3_context(Error::TrustAnchorRecovery {
            source: Box::new(Error::connect_attempt_denied(Some(1)).with_connect_prior(prior)),
            info: Box::default(),
        });
        assert!(denial.is_connect_attempt_denied());
        assert!(!denial.is_retryable());
        assert!(!denial.is_connection_closed());
        assert!(!denial.is_quic_handshake_failure());
        assert!(!denial.is_safe_to_replay());
        assert!(!denial.is_timeout());
        assert_eq!(denial.phase(), None);
        assert!(denial.as_proxy_error().is_none());
    }
}

#[test]
fn public_restoration_keeps_outer_context_and_original_error() {
    let denial = h3_context(Error::TrustAnchorRecovery {
        source: Box::new(Error::connect_attempt_denied(Some(2))),
        info: Box::default(),
    })
    .with_connect_prior(Error::connection(
        ConnectionPhase::TcpConnect,
        "original TCP error",
        None,
    ));
    assert_eq!(
        denial.connect_denial_reason(),
        Some(crate::AttemptDenialReason::ConnectLimit)
    );
    let restored = denial.into_public_connect_error();
    assert!(restored.h3_request_context().is_some());
    assert!(matches!(
        restored.h3_request_context().unwrap().source.as_ref(),
        Error::TrustAnchorRecovery { .. }
    ));
    assert!(!restored.is_connect_attempt_denied());
    assert_eq!(restored.phase(), Some(ConnectionPhase::TcpConnect));
    assert!(restored.to_string().contains("original TCP error"));
    let overflow = Error::connect_attempt_denied(None);
    assert_eq!(
        overflow.connect_denial_reason(),
        Some(crate::AttemptDenialReason::CounterExhausted)
    );
    assert!(
        matches!(overflow.into_public_connect_error(), Error::ResourceLimitExceeded(message) if message.contains("counter"))
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn mixed_protocol_failure_preserves_refusal_and_real_peer_error() {
    use crate::session::pipeline::run_protocol_race;
    use crate::session::ChromeLikeProtocolConfig;
    use std::future::Future;
    use std::pin::Pin;

    for quic_denied in [false, true] {
        for delay in [Duration::ZERO, Duration::from_secs(1)] {
            let (_selection, selected) = tokio::sync::watch::channel(None);
            let config = ChromeLikeProtocolConfig {
                tcp_main_job_delay: delay,
                keep_quic_probe_after_tcp_win: false,
                keep_tcp_probe_after_quic_win: false,
            };
            let quic_error = if quic_denied {
                Error::connect_attempt_denied(Some(1))
            } else {
                Error::QuicHandshake("real QUIC failure".into())
            };
            let tcp_error = if quic_denied {
                Error::connection(ConnectionPhase::TcpConnect, "real TCP failure", None)
            } else {
                Error::connect_attempt_denied(Some(1))
            };
            let mut tcp_error = Some(tcp_error);
            let calls = Cell::new(0);
            let error = run_protocol_race(
                config,
                selected,
                Box::pin(async move { Err::<u8, _>(quic_error) }),
                || {
                    calls.set(calls.get() + 1);
                    let error = tcp_error.take().expect("refusal must not restart TCP");
                    Box::pin(async move { Err(error) })
                        as Pin<Box<dyn Future<Output = Result<u8>> + Send>>
                },
                |_| {},
            )
            .await
            .unwrap_err();
            assert_eq!(calls.get(), 1);
            assert!(error.is_connect_attempt_denied());
            assert!(!error.is_retryable());
            let restored = error.into_public_connect_error();
            assert!(restored.to_string().contains(if quic_denied {
                "real TCP failure"
            } else {
                "real QUIC failure"
            }));
        }
    }
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn refused_quic_does_not_restart_capacity_blocked_tcp() {
    let (_selection, selected) = tokio::sync::watch::channel(None);
    let calls = Cell::new(0);
    let error = crate::session::pipeline::run_protocol_race(
        crate::session::ChromeLikeProtocolConfig {
            tcp_main_job_delay: Duration::ZERO,
            keep_quic_probe_after_tcp_win: false,
            keep_tcp_probe_after_quic_win: false,
        },
        selected,
        Box::pin(async { Err::<u8, _>(Error::connect_attempt_denied(Some(1))) }),
        || {
            calls.set(calls.get() + 1);
            Box::pin(async {
                Err(Error::Pool(
                    "session connection limit reached: fixture".into(),
                ))
            })
        },
        |_| {},
    )
    .await
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert!(error.is_connect_attempt_denied());
    assert!(matches!(error.into_public_connect_error(), Error::Pool(_)));
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn successful_peer_discards_connection_refusal() {
    for quic_wins in [false, true] {
        let (_selection, selected) = tokio::sync::watch::channel(None);
        let (ready, receiver) = tokio::sync::oneshot::channel();
        let mut ready = Some(ready);
        let result = crate::session::pipeline::run_protocol_race(
            crate::session::ChromeLikeProtocolConfig {
                tcp_main_job_delay: Duration::ZERO,
                keep_quic_probe_after_tcp_win: false,
                keep_tcp_probe_after_quic_win: false,
            },
            selected,
            Box::pin(async move {
                if quic_wins {
                    receiver.await.unwrap();
                    Ok(7u8)
                } else {
                    Err(Error::connect_attempt_denied(Some(1)))
                }
            }),
            || {
                let ready = ready.take().expect("no TCP restart after refusal");
                Box::pin(async move {
                    if quic_wins {
                        ready.send(()).unwrap();
                        Err(Error::connect_attempt_denied(Some(1)))
                    } else {
                        Ok(7u8)
                    }
                })
            },
            |_| {},
        )
        .await;
        assert_eq!(result.unwrap(), 7);
    }
}
