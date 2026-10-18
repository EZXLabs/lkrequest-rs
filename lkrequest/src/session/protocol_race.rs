use std::future::Future;
use std::pin::Pin;

use tokio::sync::watch;

use super::{is_connection_limit_error, protocol_race_error, ProtocolDecision};
use crate::error::{Error, Result};
use crate::session::ChromeLikeProtocolConfig;

pub(crate) type RaceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RaceFailureStage {
    BeforeTcpRelease,
    WaitingForPeer,
}

#[derive(Debug)]
pub(crate) enum RaceEvent<'a> {
    Won(ProtocolDecision),
    Failed {
        protocol: ProtocolDecision,
        stage: RaceFailureStage,
        error: &'a Error,
    },
}

/// Own both attempts so selecting a protocol immediately cancels its peer.
/// Only the six direct-success exits emit `Won`; callers apply the probe flags.
pub(crate) async fn run_protocol_race<'a, T>(
    config: ChromeLikeProtocolConfig,
    mut selected: watch::Receiver<Option<ProtocolDecision>>,
    mut quic_future: RaceFuture<'a, T>,
    mut tcp_factory: impl FnMut() -> RaceFuture<'a, T>,
    mut on_event: impl for<'event> FnMut(RaceEvent<'event>),
) -> Result<T> {
    if !config.tcp_main_job_delay.is_zero() {
        let mut tcp_delay = std::pin::pin!(tokio::time::sleep(config.tcp_main_job_delay));
        tokio::select! {
            biased;

            _ = selected.changed() => {
                let result = quic_future.await;
                if result.is_ok() {
                    on_event(RaceEvent::Won(ProtocolDecision::Quic));
                }
                return result;
            }
            quic_result = &mut quic_future => match quic_result {
                Ok(response) => {
                    on_event(RaceEvent::Won(ProtocolDecision::Quic));
                    return Ok(response);
                }
                Err(quic_error) => {
                    if *selected.borrow() == Some(ProtocolDecision::Quic) {
                        return Err(quic_error);
                    }
                    on_event(RaceEvent::Failed {
                        protocol: ProtocolDecision::Quic,
                        stage: RaceFailureStage::BeforeTcpRelease,
                        error: &quic_error,
                    });
                    // This early fallback has no probe notification or capacity restart.
                    return match tcp_factory().await {
                        Ok(response) => Ok(response),
                        Err(tcp_error) if selected.borrow().is_some() => Err(tcp_error),
                        Err(tcp_error) => Err(protocol_race_error(tcp_error, quic_error)),
                    };
                }
            },
            _ = &mut tcp_delay => {}
        }
    }

    let mut tcp_future = tcp_factory();
    tokio::select! {
        biased;

        _ = selected.changed() => {
            let winner = *selected.borrow();
            if winner == Some(ProtocolDecision::Quic) {
                drop(tcp_future);
                let result = quic_future.await;
                if result.is_ok() {
                    on_event(RaceEvent::Won(ProtocolDecision::Quic));
                }
                result
            } else {
                drop(quic_future);
                let result = tcp_future.await;
                if result.is_ok() {
                    on_event(RaceEvent::Won(ProtocolDecision::Tcp));
                }
                result
            }
        }
        quic_result = &mut quic_future => match quic_result {
            Ok(response) => {
                on_event(RaceEvent::Won(ProtocolDecision::Quic));
                Ok(response)
            }
            Err(quic_error) => {
                if *selected.borrow() == Some(ProtocolDecision::Quic) {
                    return Err(quic_error);
                }
                on_event(RaceEvent::Failed {
                    protocol: ProtocolDecision::Quic,
                    stage: RaceFailureStage::WaitingForPeer,
                    error: &quic_error,
                });
                match tcp_future.await {
                    Ok(response) => Ok(response),
                    Err(tcp_error) if selected.borrow().is_some() => Err(tcp_error),
                    Err(tcp_error) => {
                        finish_failed_race(tcp_error, quic_error, &selected, &mut tcp_factory).await
                    }
                }
            }
        },
        tcp_result = &mut tcp_future => match tcp_result {
            Ok(response) => {
                on_event(RaceEvent::Won(ProtocolDecision::Tcp));
                Ok(response)
            }
            Err(tcp_error) => {
                if *selected.borrow() == Some(ProtocolDecision::Tcp) {
                    return Err(tcp_error);
                }
                on_event(RaceEvent::Failed {
                    protocol: ProtocolDecision::Tcp,
                    stage: RaceFailureStage::WaitingForPeer,
                    error: &tcp_error,
                });
                match quic_future.await {
                    Ok(response) => Ok(response),
                    Err(quic_error) if selected.borrow().is_some() => Err(quic_error),
                    Err(quic_error) => {
                        finish_failed_race(tcp_error, quic_error, &selected, &mut tcp_factory).await
                    }
                }
            }
        },
    }
}

async fn finish_failed_race<'a, T>(
    tcp_error: Error,
    quic_error: Error,
    selected: &watch::Receiver<Option<ProtocolDecision>>,
    tcp_factory: &mut impl FnMut() -> RaceFuture<'a, T>,
) -> Result<T> {
    if !is_connection_limit_error(&tcp_error) {
        return Err(protocol_race_error(tcp_error, quic_error));
    }
    tcp_factory().await.map_err(|retry_error| {
        if selected.borrow().is_some() {
            retry_error
        } else {
            protocol_race_error(retry_error, quic_error)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct BranchState {
        result: Option<Result<u8>>,
        waker: Option<Waker>,
        completed: bool,
    }

    #[derive(Clone, Default)]
    struct BranchControl {
        state: Arc<Mutex<BranchState>>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl BranchControl {
        fn complete(&self, result: Result<u8>) {
            let waker = {
                let mut state = self.state.lock().unwrap();
                assert!(state.result.replace(result).is_none());
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn polls(&self) -> usize {
            self.polls.load(Ordering::SeqCst)
        }

        fn drops(&self) -> usize {
            self.drops.load(Ordering::SeqCst)
        }
    }

    struct ControlledBranch(BranchControl);

    impl Future for ControlledBranch {
        type Output = Result<u8>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.polls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.0.state.lock().unwrap();
            assert!(!state.completed, "completed attempt polled again");
            match state.result.take() {
                Some(result) => {
                    state.completed = true;
                    Poll::Ready(result)
                }
                None => {
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    impl Drop for ControlledBranch {
        fn drop(&mut self) {
            self.0.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn branch() -> (RaceFuture<'static, u8>, BranchControl) {
        let control = BranchControl::default();
        (Box::pin(ControlledBranch(control.clone())), control)
    }

    fn tcp_factory(
        futures: Vec<RaceFuture<'static, u8>>,
    ) -> (impl FnMut() -> RaceFuture<'static, u8>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut futures = VecDeque::from(futures);
        (
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                futures.pop_front().expect("unexpected TCP restart")
            },
            calls,
        )
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RecordedEvent {
        Won(ProtocolDecision),
        Failed(ProtocolDecision, RaceFailureStage, String),
    }

    fn record_events(
        events: Arc<Mutex<Vec<RecordedEvent>>>,
    ) -> impl for<'event> FnMut(RaceEvent<'event>) {
        move |event| {
            let event = match event {
                RaceEvent::Won(protocol) => RecordedEvent::Won(protocol),
                RaceEvent::Failed {
                    protocol,
                    stage,
                    error,
                } => RecordedEvent::Failed(protocol, stage, error.to_string()),
            };
            events.lock().unwrap().push(event);
        }
    }

    fn config(delay: Duration) -> ChromeLikeProtocolConfig {
        ChromeLikeProtocolConfig {
            tcp_main_job_delay: delay,
            keep_quic_probe_after_tcp_win: true,
            keep_tcp_probe_after_quic_win: true,
        }
    }

    fn failed(message: &str) -> Error {
        Error::Http(message.into())
    }

    fn capacity_error() -> Error {
        Error::Pool("session connection limit reached: test".into())
    }

    fn combined_error(error: Error) -> (crate::error::ConnectionPhase, String) {
        match error {
            Error::Connection(error) => (error.phase, error.message),
            other => panic!("expected combined race error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zero_delay_constructs_tcp_once_and_prioritizes_quic_completion() {
        let (_selected_tx, selected) = watch::channel(None);
        let (quic, quic_control) = branch();
        let (tcp, tcp_control) = branch();
        quic_control.complete(Ok(1));
        tcp_control.complete(Ok(2));
        let (factory, calls) = tcp_factory(vec![tcp]);
        let events = Arc::new(Mutex::new(Vec::new()));

        let result = run_protocol_race(
            config(Duration::ZERO),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        )
        .await;

        assert_eq!(result.unwrap(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!((quic_control.polls(), tcp_control.polls()), (1, 0));
        assert_eq!((quic_control.drops(), tcp_control.drops()), (1, 1));
        assert_eq!(
            *events.lock().unwrap(),
            vec![RecordedEvent::Won(ProtocolDecision::Quic)]
        );
    }

    #[tokio::test]
    async fn nonzero_delay_releases_tcp_once_without_requiring_quic_completion() {
        let (_selected_tx, selected) = watch::channel(None);
        let (quic, quic_control) = branch();
        let (tcp, tcp_control) = branch();
        tcp_control.complete(Ok(2));
        let (factory, calls) = tcp_factory(vec![tcp]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut race = Box::pin(run_protocol_race(
            config(Duration::from_millis(25)),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        ));

        assert!(poll_once(race.as_mut()).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tcp_control.polls(), 0);
        let result = tokio::time::timeout(Duration::from_secs(5), race)
            .await
            .expect("TCP release did not wake the coordinator");

        assert_eq!(result.unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(quic_control.drops(), 1);
        assert_eq!(
            *events.lock().unwrap(),
            vec![RecordedEvent::Won(ProtocolDecision::Tcp)]
        );
    }

    #[tokio::test]
    async fn early_quic_success_never_constructs_tcp() {
        for selected_before_completion in [false, true] {
            let (selected_tx, selected) = watch::channel(None);
            let (quic, control) = branch();
            let (factory, calls) = tcp_factory(Vec::new());
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::from_secs(3600)),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            if selected_before_completion {
                selected_tx.send(Some(ProtocolDecision::Quic)).unwrap();
                assert!(poll_once(race.as_mut()).is_pending());
            }
            control.complete(Ok(1));

            assert_eq!(race.await.unwrap(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(control.drops(), 1);
            assert_eq!(
                *events.lock().unwrap(),
                vec![RecordedEvent::Won(ProtocolDecision::Quic)]
            );
        }
    }

    #[tokio::test]
    async fn selection_drops_owned_loser_before_winner_completes() {
        for winner in [ProtocolDecision::Quic, ProtocolDecision::Tcp] {
            let (selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::ZERO),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            selected_tx.send(Some(winner)).unwrap();
            assert!(poll_once(race.as_mut()).is_pending());
            let (winner_control, loser_control) = if winner == ProtocolDecision::Quic {
                (&quic_control, &tcp_control)
            } else {
                (&tcp_control, &quic_control)
            };
            assert_eq!((winner_control.drops(), loser_control.drops()), (0, 1));
            assert!(events.lock().unwrap().is_empty());
            winner_control.complete(Ok(7));

            assert_eq!(race.await.unwrap(), 7);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(winner_control.drops(), 1);
            assert_eq!(*events.lock().unwrap(), vec![RecordedEvent::Won(winner)]);
        }
    }

    #[tokio::test]
    async fn selected_tcp_has_priority_over_both_ready_results() {
        let (selected_tx, selected) = watch::channel(None);
        let (quic, quic_control) = branch();
        let (tcp, tcp_control) = branch();
        quic_control.complete(Ok(1));
        tcp_control.complete(Ok(2));
        selected_tx.send(Some(ProtocolDecision::Tcp)).unwrap();
        let (factory, calls) = tcp_factory(vec![tcp]);
        let events = Arc::new(Mutex::new(Vec::new()));

        let result = run_protocol_race(
            config(Duration::ZERO),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        )
        .await;

        assert_eq!(result.unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!((quic_control.polls(), quic_control.drops()), (0, 1));
        assert_eq!(
            *events.lock().unwrap(),
            vec![RecordedEvent::Won(ProtocolDecision::Tcp)]
        );
    }

    #[tokio::test]
    async fn selected_failure_never_falls_back_or_restarts_tcp() {
        for winner in [ProtocolDecision::Quic, ProtocolDecision::Tcp] {
            let (selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::ZERO),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            selected_tx.send(Some(winner)).unwrap();
            assert!(poll_once(race.as_mut()).is_pending());
            let expected = if winner == ProtocolDecision::Quic {
                quic_control.complete(Err(failed("selected QUIC")));
                failed("selected QUIC").to_string()
            } else {
                tcp_control.complete(Err(capacity_error()));
                capacity_error().to_string()
            };

            assert_eq!(race.await.unwrap_err().to_string(), expected);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!((quic_control.drops(), tcp_control.drops()), (1, 1));
            assert!(events.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn branch_selection_and_failure_in_the_same_poll_prevents_fallback() {
        for (winner, delay) in [
            (ProtocolDecision::Quic, Duration::ZERO),
            (ProtocolDecision::Tcp, Duration::ZERO),
            (ProtocolDecision::Quic, Duration::from_secs(3600)),
        ] {
            let (selected_tx, selected) = watch::channel(None);
            let (pending, pending_control) = branch();
            let winner_future: RaceFuture<'static, u8> = Box::pin(async move {
                selected_tx.send(Some(winner)).unwrap();
                Err(failed("selected during poll"))
            });
            let (quic, tcp) = if winner == ProtocolDecision::Quic {
                (winner_future, pending)
            } else {
                (pending, winner_future)
            };
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));

            let result = run_protocol_race(
                config(delay),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            )
            .await;

            assert_eq!(
                result.unwrap_err().to_string(),
                failed("selected during poll").to_string()
            );
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(delay.is_zero()));
            assert_eq!(pending_control.drops(), 1);
            assert!(events.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn early_failure_fallback_has_no_win_event_or_capacity_restart() {
        for succeeds in [true, false] {
            let (_selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            quic_control.complete(Err(failed("QUIC")));
            tcp_control.complete(if succeeds {
                Ok(2)
            } else {
                Err(capacity_error())
            });
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));

            let result = run_protocol_race(
                config(Duration::from_secs(3600)),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            )
            .await;

            if succeeds {
                assert_eq!(result.unwrap(), 2);
            } else {
                let (phase, message) = combined_error(result.unwrap_err());
                assert_eq!(phase, crate::error::ConnectionPhase::QuicFallback);
                assert_eq!(
                    message,
                    format!(
                        "protocol race failed (tcp: {}; quic: {})",
                        capacity_error(),
                        failed("QUIC")
                    )
                );
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *events.lock().unwrap(),
                vec![RecordedEvent::Failed(
                    ProtocolDecision::Quic,
                    RaceFailureStage::BeforeTcpRelease,
                    failed("QUIC").to_string()
                )]
            );
        }
    }

    #[tokio::test]
    async fn delayed_selected_quic_failure_does_not_construct_tcp() {
        let (selected_tx, selected) = watch::channel(None);
        let (quic, control) = branch();
        let (factory, calls) = tcp_factory(Vec::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut race = Box::pin(run_protocol_race(
            config(Duration::from_secs(3600)),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        ));
        assert!(poll_once(race.as_mut()).is_pending());
        selected_tx.send(Some(ProtocolDecision::Quic)).unwrap();
        assert!(poll_once(race.as_mut()).is_pending());
        control.complete(Err(failed("selected QUIC")));

        assert_eq!(
            race.await.unwrap_err().to_string(),
            failed("selected QUIC").to_string()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn early_fallback_preserves_an_error_after_tcp_is_selected() {
        let (selected_tx, selected) = watch::channel(None);
        let (quic, quic_control) = branch();
        let (tcp, tcp_control) = branch();
        quic_control.complete(Err(failed("QUIC")));
        let (factory, calls) = tcp_factory(vec![tcp]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut race = Box::pin(run_protocol_race(
            config(Duration::from_secs(3600)),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        ));
        assert!(poll_once(race.as_mut()).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        selected_tx.send(Some(ProtocolDecision::Tcp)).unwrap();
        tcp_control.complete(Err(capacity_error()));

        assert_eq!(
            race.await.unwrap_err().to_string(),
            capacity_error().to_string()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock().unwrap(),
            vec![RecordedEvent::Failed(
                ProtocolDecision::Quic,
                RaceFailureStage::BeforeTcpRelease,
                failed("QUIC").to_string()
            )]
        );
    }

    #[tokio::test]
    async fn peer_failure_reports_both_errors_in_tcp_quic_order() {
        for first in [ProtocolDecision::Quic, ProtocolDecision::Tcp] {
            let (_selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::ZERO),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            let (first_control, second_control, first_name, second_name) =
                if first == ProtocolDecision::Quic {
                    (&quic_control, &tcp_control, "QUIC", "TCP")
                } else {
                    (&tcp_control, &quic_control, "TCP", "QUIC")
                };
            first_control.complete(Err(failed(first_name)));
            assert!(poll_once(race.as_mut()).is_pending());
            second_control.complete(Err(failed(second_name)));
            let (phase, message) = combined_error(race.await.unwrap_err());

            assert_eq!(phase, crate::error::ConnectionPhase::QuicFallback);
            assert_eq!(
                message,
                format!(
                    "protocol race failed (tcp: {}; quic: {})",
                    failed("TCP"),
                    failed("QUIC")
                )
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *events.lock().unwrap(),
                vec![RecordedEvent::Failed(
                    first,
                    RaceFailureStage::WaitingForPeer,
                    failed(first_name).to_string()
                )]
            );
        }
    }

    #[tokio::test]
    async fn peer_success_after_failure_does_not_emit_a_win_event() {
        for first in [ProtocolDecision::Quic, ProtocolDecision::Tcp] {
            let (_selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            let (factory, calls) = tcp_factory(vec![tcp]);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::ZERO),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            let (first_control, second_control) = if first == ProtocolDecision::Quic {
                (&quic_control, &tcp_control)
            } else {
                (&tcp_control, &quic_control)
            };
            first_control.complete(Err(failed("first")));
            assert!(poll_once(race.as_mut()).is_pending());
            second_control.complete(Ok(9));

            assert_eq!(race.await.unwrap(), 9);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *events.lock().unwrap(),
                vec![RecordedEvent::Failed(
                    first,
                    RaceFailureStage::WaitingForPeer,
                    failed("first").to_string()
                )]
            );
        }
    }

    #[tokio::test]
    async fn capacity_failure_restarts_tcp_once_for_either_completion_order() {
        for first in [ProtocolDecision::Quic, ProtocolDecision::Tcp] {
            for retry_succeeds in [false, true] {
                let (_selected_tx, selected) = watch::channel(None);
                let (quic, quic_control) = branch();
                let (tcp, tcp_control) = branch();
                let (retry, retry_control) = branch();
                let (factory, calls) = tcp_factory(vec![tcp, retry]);
                let events = Arc::new(Mutex::new(Vec::new()));
                let mut race = Box::pin(run_protocol_race(
                    config(Duration::ZERO),
                    selected,
                    quic,
                    factory,
                    record_events(events.clone()),
                ));
                assert!(poll_once(race.as_mut()).is_pending());
                if first == ProtocolDecision::Quic {
                    quic_control.complete(Err(failed("QUIC")));
                } else {
                    tcp_control.complete(Err(capacity_error()));
                }
                assert!(poll_once(race.as_mut()).is_pending());
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                if first == ProtocolDecision::Quic {
                    tcp_control.complete(Err(capacity_error()));
                } else {
                    quic_control.complete(Err(failed("QUIC")));
                }
                assert!(poll_once(race.as_mut()).is_pending());
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                retry_control.complete(if retry_succeeds {
                    Ok(3)
                } else {
                    Err(capacity_error())
                });

                let result = race.await;
                if retry_succeeds {
                    assert_eq!(result.unwrap(), 3);
                } else {
                    let (_, message) = combined_error(result.unwrap_err());
                    assert_eq!(
                        message,
                        format!(
                            "protocol race failed (tcp: {}; quic: {})",
                            capacity_error(),
                            failed("QUIC")
                        )
                    );
                }
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert_eq!(retry_control.drops(), 1);
                let expected_error = if first == ProtocolDecision::Quic {
                    failed("QUIC")
                } else {
                    capacity_error()
                };
                assert_eq!(
                    *events.lock().unwrap(),
                    vec![RecordedEvent::Failed(
                        first,
                        RaceFailureStage::WaitingForPeer,
                        expected_error.to_string()
                    )]
                );
            }
        }
    }

    #[tokio::test]
    async fn selection_during_peer_or_retry_wait_preserves_the_selected_error() {
        for (first, restart) in [
            (ProtocolDecision::Quic, false),
            (ProtocolDecision::Tcp, false),
            (ProtocolDecision::Quic, true),
            (ProtocolDecision::Tcp, true),
        ] {
            let (selected_tx, selected) = watch::channel(None);
            let (quic, quic_control) = branch();
            let (tcp, tcp_control) = branch();
            let (retry, retry_control) = branch();
            let (factory, calls) = tcp_factory(vec![tcp, retry]);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut race = Box::pin(run_protocol_race(
                config(Duration::ZERO),
                selected,
                quic,
                factory,
                record_events(events.clone()),
            ));
            assert!(poll_once(race.as_mut()).is_pending());
            if first == ProtocolDecision::Quic {
                quic_control.complete(Err(failed("QUIC")));
            } else {
                tcp_control.complete(Err(capacity_error()));
            }
            assert!(poll_once(race.as_mut()).is_pending());
            if restart {
                if first == ProtocolDecision::Quic {
                    tcp_control.complete(Err(capacity_error()));
                } else {
                    quic_control.complete(Err(failed("QUIC")));
                }
                assert!(poll_once(race.as_mut()).is_pending());
            }
            let expected = if restart {
                selected_tx.send(Some(ProtocolDecision::Tcp)).unwrap();
                retry_control.complete(Err(failed("selected TCP")));
                failed("selected TCP")
            } else if first == ProtocolDecision::Quic {
                selected_tx.send(Some(ProtocolDecision::Tcp)).unwrap();
                tcp_control.complete(Err(capacity_error()));
                capacity_error()
            } else {
                selected_tx.send(Some(ProtocolDecision::Quic)).unwrap();
                quic_control.complete(Err(failed("selected QUIC")));
                failed("selected QUIC")
            };

            assert_eq!(race.await.unwrap_err().to_string(), expected.to_string());
            assert_eq!(calls.load(Ordering::SeqCst), if restart { 2 } else { 1 });
            assert_eq!(events.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn cancelling_the_coordinator_drops_both_attempts_without_background_work() {
        let (_selected_tx, selected) = watch::channel(None);
        let (quic, quic_control) = branch();
        let (tcp, tcp_control) = branch();
        let (factory, calls) = tcp_factory(vec![tcp]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut race = Box::pin(run_protocol_race(
            config(Duration::ZERO),
            selected,
            quic,
            factory,
            record_events(events.clone()),
        ));
        assert!(poll_once(race.as_mut()).is_pending());
        assert_eq!((quic_control.polls(), tcp_control.polls()), (1, 1));
        drop(race);

        assert_eq!((quic_control.drops(), tcp_control.drops()), (1, 1));
        quic_control.complete(Ok(1));
        tcp_control.complete(Ok(2));
        tokio::task::yield_now().await;
        assert_eq!((quic_control.polls(), tcp_control.polls()), (1, 1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(events.lock().unwrap().is_empty());
    }
}
