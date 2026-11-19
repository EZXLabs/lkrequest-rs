//! Explicit authority for one public operation and its child attempts.

use std::cell::Cell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::future::Either;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::attempts::{
    AttemptDenialReason, AttemptOutcome, AttemptSummary, EffectiveAttemptLimits,
};
use crate::error::{Error, Result};
use crate::timeout::RequestTimeout;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Active,
    Published,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptKind {
    Normal,
    Extra,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptStatus {
    Issued,
    Reserved,
    Released,
    Committed,
}

#[derive(Clone, Copy)]
struct AttemptState {
    generation: u64,
    kind: AttemptKind,
    status: AttemptStatus,
}

struct State {
    lifecycle: Lifecycle,
    http_attempts: u64,
    recoveries: u64,
    extra_http: u64,
    redirects: u64,
    connect_initiations: u64,
    probe_suppressed_by_connect_limit: bool,
    current: Option<AttemptState>,
    tai_used: bool,
    denial_reason: Option<AttemptDenialReason>,
    terminal_denied: bool,
}

impl State {
    fn counter_exhausted(&mut self) -> Error {
        self.terminal_denied = true;
        self.denial_reason = Some(AttemptDenialReason::CounterExhausted);
        counter_exhausted()
    }
}

struct Inner {
    state: Mutex<State>,
    stopped: Notify,
    inactive: AtomicBool,
    timeout: RequestTimeout,
    limits: Option<EffectiveAttemptLimits>,
}

impl Inner {
    fn new(timeout: RequestTimeout, limits: Option<EffectiveAttemptLimits>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                lifecycle: Lifecycle::Active,
                http_attempts: 0,
                recoveries: 0,
                extra_http: 0,
                redirects: 0,
                connect_initiations: 0,
                probe_suppressed_by_connect_limit: false,
                current: None,
                tai_used: false,
                denial_reason: None,
                terminal_denied: false,
            }),
            stopped: Notify::new(),
            inactive: AtomicBool::new(false),
            timeout,
            limits,
        })
    }

    fn check(&self, state: &State) -> Result<()> {
        self.timeout.check()?;
        if state.lifecycle != Lifecycle::Active {
            return Err(Error::Http("request execution is no longer active".into()));
        }
        Ok(())
    }

    fn check_active(&self) -> Result<()> {
        if self.inactive.load(Ordering::Acquire) {
            return Err(Error::Http("request execution is no longer active".into()));
        }
        Ok(())
    }

    fn check_connect_budget(&self, state: &State) -> Result<()> {
        self.check(state)?;
        let limits = self.limits.ok_or_else(|| {
            Error::InvalidConfig("connection attempt limits were not resolved".into())
        })?;
        if let Some(limit) = limits.connect_attempts() {
            if state.connect_initiations >= limit {
                return Err(Error::connect_attempt_denied(Some(limit)));
            }
        }
        if state.connect_initiations == u64::MAX {
            return Err(Error::connect_attempt_denied(None));
        }
        Ok(())
    }

    fn check_http_budget(&self, state: &mut State, kind: AttemptKind) -> Result<()> {
        if state.terminal_denied {
            return Err(Error::ResourceLimitExceeded(
                "request attempts are exhausted".into(),
            ));
        }
        if kind == AttemptKind::Extra
            && self
                .limits
                .and_then(|limits| limits.extra_http_attempts())
                .is_some_and(|limit| state.extra_http >= limit)
        {
            state.terminal_denied = true;
            state.denial_reason = Some(AttemptDenialReason::ExtraHttpLimit);
            return Err(Error::ResourceLimitExceeded(
                "extra HTTP attempt limit exhausted".into(),
            ));
        }
        Ok(())
    }

    fn stopped(&self) -> impl Future<Output = ()> + '_ {
        // notify_waiters covers Notified from creation, including before its
        // first poll. Create it before reading the permanent stop flag.
        let notified = self.stopped.notified();
        if self.inactive.load(Ordering::Acquire) {
            Either::Left(std::future::ready(()))
        } else {
            Either::Right(notified)
        }
    }

    async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        self.check_active()?;
        // Borrow the pinned workflow so deadline/select wrappers do not copy
        // its large state into each nested future.
        tokio::pin!(future);
        let result = tokio::select! {
            biased;
            _ = self.stopped() => Err(Error::Http("request execution is no longer active".into())),
            result = self.timeout.run(&mut future) => result,
        };
        self.check_active()?;
        result
    }
}

/// Kept only by the public entry point, never by a child or connection driver.
pub(crate) struct ExecutionGuard {
    inner: Arc<Inner>,
    finalized: Cell<bool>,
}

impl ExecutionGuard {
    pub(crate) fn run<'a, T: 'a>(
        &'a mut self,
        future: impl Future<Output = Result<T>> + 'a,
    ) -> impl Future<Output = Result<T>> + 'a {
        let inner = self.inner.as_ref();
        async move {
            // The exclusive guard borrow prevents finalization while the root
            // runs. Only independently owned children need a stop listener.
            inner.check_active()?;
            tokio::pin!(future);
            let result = inner.timeout.run(&mut future).await;
            inner.check_active()?;
            result
        }
    }

    pub(crate) fn finish_error(&self, error: &Error) {
        let mut state = self.inner.state.lock();
        if state.lifecycle != Lifecycle::Active {
            return;
        }
        state.lifecycle = Lifecycle::Failed;
        if let Some(reason) = error.connect_denial_reason() {
            state.denial_reason = Some(reason);
        } else if error.is_timeout() {
            state.denial_reason = Some(AttemptDenialReason::Deadline);
        } else if state.denial_reason.is_none() {
            state.denial_reason = if error.is_timeout() {
                Some(AttemptDenialReason::Deadline)
            } else if matches!(error, Error::InvalidConfig(_)) {
                Some(AttemptDenialReason::InvalidConfiguration)
            } else {
                None
            };
        }
        self.inner.inactive.store(true, Ordering::Release);
        drop(state);
        self.finalized.set(true);
        self.inner.stopped.notify_waiters();
    }

    pub(crate) fn publish(&self) -> Result<()> {
        let mut state = self.inner.state.lock();
        self.inner.check(&state)?;
        state.lifecycle = Lifecycle::Published;
        self.inner.inactive.store(true, Ordering::Release);
        drop(state);
        self.finalized.set(true);
        self.inner.stopped.notify_waiters();
        Ok(())
    }
}

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        if self.finalized.get() {
            return;
        }
        let mut state = self.inner.state.lock();
        if state.lifecycle == Lifecycle::Active {
            state.lifecycle = Lifecycle::Stopped;
            state.denial_reason = Some(AttemptDenialReason::Cancelled);
        }
        self.inner.inactive.store(true, Ordering::Release);
        drop(state);
        self.inner.stopped.notify_waiters();
    }
}

#[derive(Clone)]
pub(crate) struct RequestExecution {
    inner: Arc<Inner>,
}

impl RequestExecution {
    #[cfg(test)]
    pub(crate) fn new(timeout: RequestTimeout) -> (Self, ExecutionGuard) {
        Self::with_limits(timeout, Some(EffectiveAttemptLimits::default()))
    }

    pub(crate) fn with_limits(
        timeout: RequestTimeout,
        limits: Option<EffectiveAttemptLimits>,
    ) -> (Self, ExecutionGuard) {
        let inner = Inner::new(timeout, limits);
        let guard = ExecutionGuard {
            inner: inner.clone(),
            finalized: Cell::new(false),
        };
        (Self { inner }, guard)
    }

    pub(crate) fn ensure_active(&self) -> Result<()> {
        self.inner.check_active()?;
        self.inner.timeout.check()
    }

    pub(crate) fn run<'a, T: 'a>(
        &'a self,
        future: impl Future<Output = Result<T>> + 'a,
    ) -> impl Future<Output = Result<T>> + 'a {
        self.inner.run(future)
    }

    pub(crate) fn connection(&self) -> ConnectionExecution {
        ConnectionExecution {
            inner: self.inner.clone(),
            tai_scope: TaiScope::Operation,
        }
    }

    pub(crate) fn has_connect_limit(&self) -> bool {
        self.inner
            .limits
            .and_then(|limits| limits.connect_attempts())
            .is_some()
    }

    pub(crate) fn submissions(&self) -> u64 {
        self.inner.state.lock().http_attempts
    }

    pub(crate) fn record_connect_denial(&self, error: &Error) {
        if let Some(reason) = error.connect_denial_reason() {
            let mut state = self.inner.state.lock();
            if state.lifecycle == Lifecycle::Active {
                state.denial_reason = Some(reason);
            }
        }
    }

    pub(crate) fn start_http(&self) -> Result<(HttpAttempt, RecoveryOwner)> {
        let mut state = self.inner.state.lock();
        self.inner.check(&state)?;
        if self.inner.limits.is_none() {
            state.denial_reason = Some(AttemptDenialReason::InvalidConfiguration);
            return Err(Error::InvalidConfig(
                "request attempt limits were not resolved".into(),
            ));
        }
        if state.current.is_some() {
            return Err(Error::Http("initial HTTP authority already issued".into()));
        }
        state.current = Some(AttemptState {
            generation: 1,
            kind: AttemptKind::Normal,
            status: AttemptStatus::Issued,
        });
        Ok((
            HttpAttempt {
                execution: self.clone(),
                generation: 1,
            },
            RecoveryOwner {
                execution: self.clone(),
            },
        ))
    }

    fn recover(
        &self,
        expected_generation: Option<u64>,
        kind: &'static str,
        submitted_since: Option<u64>,
        allow_submitted: bool,
    ) -> Option<HttpAttempt> {
        let (generation, recovery) = {
            let mut state = self.inner.state.lock();
            self.inner.check(&state).ok()?;
            let current = state.current?;
            if state.terminal_denied
                || expected_generation.is_some_and(|expected| expected != current.generation)
                || current.status == AttemptStatus::Reserved
            {
                return None;
            }
            if current.status == AttemptStatus::Committed && !allow_submitted {
                state.denial_reason = Some(AttemptDenialReason::ReplayDenied);
                return None;
            }
            let Some(recovery) = state.recoveries.checked_add(1) else {
                state.counter_exhausted();
                return None;
            };
            let kind = if current.status == AttemptStatus::Committed
                || submitted_since.is_some_and(|start| state.http_attempts > start)
            {
                AttemptKind::Extra
            } else {
                current.kind
            };
            // The sole issued generation owns the available entitlement before
            // backoff; only its commit charges usage.
            self.inner.check_http_budget(&mut state, kind).ok()?;
            let generation = if current.status == AttemptStatus::Issued && kind == current.kind {
                current.generation
            } else {
                let Some(generation) = current.generation.checked_add(1) else {
                    state.counter_exhausted();
                    return None;
                };
                generation
            };
            state.current = Some(AttemptState {
                generation,
                kind,
                status: AttemptStatus::Issued,
            });
            state.recoveries = recovery;
            state.denial_reason = None;
            (generation, recovery)
        };
        tracing::trace!(recovery, kind, "http.recovery_authorized");
        Some(HttpAttempt {
            execution: self.clone(),
            generation,
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (u64, u64) {
        let state = self.inner.state.lock();
        (state.http_attempts, state.recoveries)
    }

    pub(crate) fn snapshot_summary(&self) -> AttemptSummary {
        let state = self.inner.state.lock();
        AttemptSummary {
            started: true,
            effective_limits: self.inner.limits,
            http_submissions: state.http_attempts,
            extra_http_submissions: state.extra_http,
            redirects: state.redirects,
            recoveries: state.recoveries,
            connect_initiations: state.connect_initiations,
            probe_suppressed_by_connect_limit: state.probe_suppressed_by_connect_limit,
            outcome: match state.lifecycle {
                Lifecycle::Active => AttemptOutcome::Active,
                Lifecycle::Published => AttemptOutcome::Succeeded,
                Lifecycle::Failed => AttemptOutcome::Failed,
                Lifecycle::Stopped => AttemptOutcome::Cancelled,
            },
            denial_reason: state.denial_reason,
        }
    }

    #[cfg(test)]
    fn attempt_counts(&self) -> (u64, u64, u64) {
        let state = self.inner.state.lock();
        (state.http_attempts, state.extra_http, state.redirects)
    }
}

/// One immutable generation; cloning shares its single submission entitlement.
#[derive(Clone)]
pub(crate) struct HttpAttempt {
    execution: RequestExecution,
    generation: u64,
}

impl HttpAttempt {
    pub(crate) fn record_denial(&self, reason: AttemptDenialReason) {
        let mut state = self.execution.inner.state.lock();
        if state.lifecycle == Lifecycle::Active
            && !state.terminal_denied
            && state
                .current
                .is_some_and(|current| current.generation == self.generation)
        {
            state.denial_reason = Some(reason);
        }
    }

    pub(crate) fn take(&self) -> Result<HttpPermit> {
        let mut state = self.execution.inner.state.lock();
        self.execution.inner.check(&state)?;
        let current = state.current.ok_or_else(missing_attempt)?;
        if current.generation != self.generation || current.status != AttemptStatus::Issued {
            return Err(Error::Http("HTTP attempt authority is unavailable".into()));
        }
        self.execution
            .inner
            .check_http_budget(&mut state, current.kind)?;
        state.current = Some(AttemptState {
            status: AttemptStatus::Reserved,
            ..current
        });
        Ok(HttpPermit {
            attempt: self.clone(),
            committed: false,
        })
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn was_submitted(&self) -> bool {
        let state = self.execution.inner.state.lock();
        state.current.is_none_or(|current| {
            current.generation != self.generation || current.status == AttemptStatus::Committed
        })
    }

    pub(crate) fn recover(&self, kind: &'static str) -> Option<Self> {
        self.execution
            .recover(Some(self.generation), kind, None, true)
    }

    pub(crate) fn recover_reconstruction(
        &self,
        kind: &'static str,
        replay_safe: bool,
    ) -> Option<Self> {
        self.execution
            .recover(Some(self.generation), kind, None, replay_safe)
    }
}

/// Orchestration-only authority; never stored on a clonable race candidate.
pub(crate) struct RecoveryOwner {
    execution: RequestExecution,
}

impl RecoveryOwner {
    pub(crate) fn is_terminal_denied(&self) -> bool {
        self.execution.inner.state.lock().terminal_denied
    }

    pub(crate) fn record_denial(&self, reason: AttemptDenialReason) {
        let mut state = self.execution.inner.state.lock();
        if state.lifecycle == Lifecycle::Active && !state.terminal_denied {
            state.denial_reason = Some(reason);
        }
    }

    #[cfg(any(feature = "quic-h3", test))]
    pub(crate) fn hop_owner(&self) -> Self {
        Self {
            execution: self.execution.clone(),
        }
    }

    pub(crate) fn submissions(&self) -> u64 {
        self.execution.inner.state.lock().http_attempts
    }

    pub(crate) fn recover(
        &self,
        kind: &'static str,
        submitted_since: Option<u64>,
    ) -> Option<HttpAttempt> {
        self.execution.recover(None, kind, submitted_since, true)
    }

    pub(crate) fn redirect(&self) -> Result<HttpAttempt> {
        let mut state = self.execution.inner.state.lock();
        self.execution.inner.check(&state)?;
        let current = state.current.ok_or_else(missing_attempt)?;
        if current.status != AttemptStatus::Committed {
            return Err(Error::Http(
                "redirect requires a committed HTTP attempt".into(),
            ));
        }
        self.execution
            .inner
            .check_http_budget(&mut state, AttemptKind::Normal)?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| state.counter_exhausted())?;
        let redirects = state
            .redirects
            .checked_add(1)
            .ok_or_else(|| state.counter_exhausted())?;
        state.current = Some(AttemptState {
            generation,
            kind: AttemptKind::Normal,
            status: AttemptStatus::Issued,
        });
        state.redirects = redirects;
        Ok(HttpAttempt {
            execution: self.execution.clone(),
            generation,
        })
    }
}

pub(crate) struct HttpPermit {
    attempt: HttpAttempt,
    committed: bool,
}

impl HttpPermit {
    pub(crate) fn commit(mut self, protocol: &'static str) -> Result<SubmissionToken> {
        let count = {
            let mut state = self.attempt.execution.inner.state.lock();
            self.attempt.execution.inner.check(&state)?;
            let current = state.current.ok_or_else(missing_attempt)?;
            if current.generation != self.attempt.generation
                || current.status != AttemptStatus::Reserved
            {
                return Err(Error::Http("HTTP permit is no longer current".into()));
            }
            self.attempt
                .execution
                .inner
                .check_http_budget(&mut state, current.kind)?;
            let count = state
                .http_attempts
                .checked_add(1)
                .ok_or_else(|| state.counter_exhausted())?;
            let extra = match current.kind {
                AttemptKind::Normal => state.extra_http,
                AttemptKind::Extra => state
                    .extra_http
                    .checked_add(1)
                    .ok_or_else(|| state.counter_exhausted())?,
            };
            state.http_attempts = count;
            state.extra_http = extra;
            state.current = Some(AttemptState {
                status: AttemptStatus::Committed,
                ..current
            });
            self.committed = true;
            count
        };
        tracing::trace!(attempt = count, protocol, "http.attempt_committed");
        Ok(SubmissionToken { _private: () })
    }
}

impl Drop for HttpPermit {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut state = self.attempt.execution.inner.state.lock();
        if let Some(current) = state.current.as_mut() {
            if current.generation == self.attempt.generation
                && current.status == AttemptStatus::Reserved
            {
                current.status = AttemptStatus::Released;
            }
        }
    }
}

pub(crate) struct SubmissionToken {
    _private: (),
}

impl SubmissionToken {
    pub(crate) fn submit<T>(self, operation: impl FnOnce() -> T) -> T {
        operation()
    }
}

fn missing_attempt() -> Error {
    Error::Http("missing HTTP attempt authority".into())
}

fn counter_exhausted() -> Error {
    Error::Http("HTTP attempt counter exhausted".into())
}

#[derive(Clone, Copy)]
enum TaiScope {
    Operation,
    #[cfg(feature = "quic-h3")]
    Handshake,
}

/// Connection-only work cannot acquire HTTP submission authority.
#[derive(Clone)]
pub(crate) struct ConnectionExecution {
    inner: Arc<Inner>,
    tai_scope: TaiScope,
}

impl ConnectionExecution {
    #[cfg(feature = "quic-h3")]
    pub(crate) fn has_connect_limit(&self) -> bool {
        self.inner
            .limits
            .and_then(|limits| limits.connect_attempts())
            .is_some()
    }

    pub(crate) fn ensure_active(&self) -> Result<()> {
        self.inner.check_active()?;
        self.inner.timeout.check()
    }

    pub(crate) fn new() -> (Self, ExecutionGuard) {
        Self::with_limits(EffectiveAttemptLimits::default())
    }

    pub(crate) fn with_limits(limits: EffectiveAttemptLimits) -> (Self, ExecutionGuard) {
        Self::with_tai_scope(TaiScope::Operation, limits)
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn background() -> (Self, ExecutionGuard) {
        // Detached probes historically have a local recovery window per handshake.
        Self::with_tai_scope(TaiScope::Handshake, EffectiveAttemptLimits::default())
    }

    fn with_tai_scope(
        tai_scope: TaiScope,
        limits: EffectiveAttemptLimits,
    ) -> (Self, ExecutionGuard) {
        let inner = Inner::new(RequestTimeout::default(), Some(limits));
        let guard = ExecutionGuard {
            inner: inner.clone(),
            finalized: Cell::new(false),
        };
        (Self { inner, tai_scope }, guard)
    }

    /// Call only after local preparation, immediately before backend initiation.
    pub(crate) fn commit_start(&self, transport: &'static str) -> Result<()> {
        let count = {
            let mut state = self.inner.state.lock();
            self.inner.check_connect_budget(&state)?;
            let count = state
                .connect_initiations
                .checked_add(1)
                .ok_or_else(|| Error::connect_attempt_denied(None))?;
            state.connect_initiations = count;
            count
        };
        tracing::trace!(attempt = count, transport, "connect.attempt_committed");
        Ok(())
    }

    /// A scheduling hint only; it neither reserves nor authorizes a start.
    pub(crate) fn check_start_allowed(&self) -> Result<()> {
        self.inner.check_connect_budget(&self.inner.state.lock())
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn allow_background_probe(&self) -> bool {
        let mut state = self.inner.state.lock();
        if self.inner.check(&state).is_err() {
            return false;
        }
        if self
            .inner
            .limits
            .and_then(|limits| limits.connect_attempts())
            .is_none()
        {
            return true;
        }
        state.probe_suppressed_by_connect_limit = true;
        drop(state);
        tracing::debug!("probe_suppressed_by_connect_limit");
        false
    }

    pub(crate) fn run<'a, T: 'a>(
        &'a self,
        future: impl Future<Output = Result<T>> + 'a,
    ) -> impl Future<Output = Result<T>> + 'a {
        self.inner.run(future)
    }

    pub(crate) fn consume_tai_budget(&self) -> bool {
        let mut state = self.inner.state.lock();
        if self.inner.check(&state).is_err() {
            return false;
        }
        match self.tai_scope {
            TaiScope::Operation => !std::mem::replace(&mut state.tai_used, true),
            #[cfg(feature = "quic-h3")]
            TaiScope::Handshake => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempts::{AttemptLimitScope, AttemptLimits};

    fn limited_execution(limit: u64) -> (RequestExecution, ExecutionGuard) {
        let limits = AttemptLimits::default()
            .with_extra_http_attempts(limit)
            .resolve(None, AttemptLimitScope::Client)
            .unwrap();
        RequestExecution::with_limits(RequestTimeout::default(), Some(limits))
    }

    fn connect_limited_execution(limit: u64) -> (RequestExecution, ExecutionGuard) {
        let limits = AttemptLimits::default()
            .with_connect_attempts(limit)
            .resolve(None, AttemptLimitScope::Request)
            .unwrap();
        RequestExecution::with_limits(RequestTimeout::default(), Some(limits))
    }

    #[test]
    fn connection_candidates_share_last_start_without_poisoning_http() {
        let (execution, guard) = connect_limited_execution(1);
        let barrier = std::sync::Barrier::new(8);
        let accepted = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let connection = execution.connection();
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        connection.commit_start("test").is_ok()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|accepted| *accepted)
                .count()
        });
        assert_eq!(accepted, 1);
        assert_eq!(execution.snapshot_summary().connect_initiations(), 1);
        let error = execution.connection().commit_start("test").unwrap_err();
        assert!(error.is_connect_attempt_denied());
        let (attempt, _) = execution.start_http().unwrap();
        commit(&attempt);
        guard.publish().unwrap();
        assert_eq!(execution.snapshot_summary().denial_reason(), None);
        assert_eq!(
            execution.snapshot_summary().outcome(),
            AttemptOutcome::Succeeded
        );
    }

    #[test]
    fn connection_refusal_is_selected_only_at_finalization() {
        let (execution, guard) = connect_limited_execution(0);
        let error = execution.connection().commit_start("tcp").unwrap_err();
        assert_eq!(execution.snapshot_summary().denial_reason(), None);
        assert_eq!(execution.snapshot_summary().connect_initiations(), 0);
        guard.finish_error(&error);
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ConnectLimit)
        );
        assert!(matches!(
            error.into_public_connect_error(),
            Error::ResourceLimitExceeded(_)
        ));
    }

    #[test]
    fn connection_cancellation_and_overflow_never_charge_another_start() {
        let (execution, guard) = connect_limited_execution(3);
        execution.connection().commit_start("tcp").unwrap();
        drop(guard);
        assert!(execution.connection().commit_start("quic").is_err());
        assert_eq!(execution.snapshot_summary().connect_initiations(), 1);
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        execution.inner.state.lock().connect_initiations = u64::MAX;
        let error = execution.connection().commit_start("tcp").unwrap_err();
        assert_eq!(execution.snapshot_summary().connect_initiations(), u64::MAX);
        guard.finish_error(&error);
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::CounterExhausted)
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn finite_connect_limit_suppresses_detached_probe_without_denial() {
        let (execution, guard) = connect_limited_execution(4);
        assert!(!execution.connection().allow_background_probe());
        guard.publish().unwrap();
        let summary = execution.snapshot_summary();
        assert!(summary.probe_suppressed_by_connect_limit());
        assert_eq!(summary.denial_reason(), None);
        assert_eq!(summary.connect_initiations(), 0);
        assert!(!execution.connection().allow_background_probe());
        assert_eq!(execution.snapshot_summary(), summary);
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        assert!(execution.connection().allow_background_probe());
        drop(guard);
        let summary = execution.snapshot_summary();
        assert!(!execution.connection().allow_background_probe());
        assert_eq!(execution.snapshot_summary(), summary);
    }

    fn commit(attempt: &HttpAttempt) {
        assert!(attempt
            .take()
            .unwrap()
            .commit("h2")
            .unwrap()
            .submit(|| true));
    }

    fn assert_count_bound(execution: &RequestExecution) {
        let (total, extra, redirects) = execution.attempt_counts();
        assert!(u128::from(total) <= 1 + u128::from(redirects) + u128::from(extra));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AuthoritySnapshot {
        submissions: u64,
        recoveries: u64,
        extra: u64,
        redirects: u64,
        generation: u64,
        kind: u8,
        status: u8,
    }

    fn authority_snapshot(execution: &RequestExecution) -> AuthoritySnapshot {
        let state = execution.inner.state.lock();
        let current = state.current.unwrap();
        AuthoritySnapshot {
            submissions: state.http_attempts,
            recoveries: state.recoveries,
            extra: state.extra_http,
            redirects: state.redirects,
            generation: current.generation,
            kind: current.kind as u8,
            status: current.status as u8,
        }
    }

    #[test]
    fn finite_caps_allow_exactly_the_committed_extra_allowance() {
        for limit in [0, 1, 3] {
            let (execution, guard) = limited_execution(limit);
            let (mut attempt, owner) = execution.start_http().unwrap();
            commit(&attempt);
            for used in 0..limit {
                attempt = attempt.recover("connection_closed").unwrap();
                assert_eq!(execution.attempt_counts(), (1 + used, used, 0));
                commit(&attempt);
                assert_eq!(execution.attempt_counts(), (2 + used, used + 1, 0));
            }
            let before = authority_snapshot(&execution);
            assert!(attempt.recover("connection_closed").is_none());
            assert_eq!(authority_snapshot(&execution), before);
            assert!(owner.is_terminal_denied());
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::ExtraHttpLimit)
            );
            assert!(owner.recover("application_error", None).is_none());
            assert_eq!(authority_snapshot(&execution), before);
            assert_count_bound(&execution);
            guard.publish().unwrap();
        }
    }

    #[test]
    fn concurrent_candidates_share_the_last_extra_submission() {
        for limit in [1, 3] {
            let (execution, _guard) = limited_execution(limit);
            let (mut attempt, _owner) = execution.start_http().unwrap();
            commit(&attempt);
            for _ in 1..limit {
                attempt = attempt.recover("connection_closed").unwrap();
                commit(&attempt);
            }
            let last = attempt.recover("connection_closed").unwrap();
            let start = std::sync::Barrier::new(8);
            let reserved = std::sync::Barrier::new(8);
            let submitted = std::thread::scope(|scope| {
                let threads: Vec<_> = (0..8)
                    .map(|_| {
                        let candidate = last.clone();
                        let start = &start;
                        let reserved = &reserved;
                        scope.spawn(move || {
                            start.wait();
                            let permit = candidate.take();
                            reserved.wait();
                            match permit {
                                Ok(permit) => permit.commit("h2").unwrap().submit(|| true),
                                Err(_) => false,
                            }
                        })
                    })
                    .collect();
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .filter(|submitted| *submitted)
                    .count()
            });
            assert_eq!(submitted, 1);
            assert_eq!(execution.attempt_counts(), (limit + 1, limit, 0));
            assert_eq!(execution.snapshot_summary().denial_reason(), None);
            assert!(last.recover("another_retry").is_none());
            assert_eq!(execution.attempt_counts(), (limit + 1, limit, 0));
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::ExtraHttpLimit)
            );
            assert_count_bound(&execution);
        }
    }

    #[test]
    fn abandoned_extra_reservation_releases_its_unspent_allowance() {
        let (execution, _guard) = limited_execution(1);
        let (initial, _owner) = execution.start_http().unwrap();
        commit(&initial);
        let extra = initial.recover("connection_closed").unwrap();
        let permit = extra.take().unwrap();
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
        drop(permit);
        assert!(extra.take().is_err());
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
        let replacement = extra.recover("preparation_failed").unwrap();
        assert_ne!(replacement.generation, extra.generation);
        assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Extra);
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
        commit(&replacement);
        assert_eq!(execution.attempt_counts(), (2, 1, 0));
        assert!(replacement.recover("another_retry").is_none());
        assert_eq!(execution.attempt_counts(), (2, 1, 0));
        assert_count_bound(&execution);
    }

    #[test]
    fn backend_refusal_consumes_finite_extra_allowance() {
        for limit in [0, 1, 3] {
            let (execution, guard) = limited_execution(limit);
            let (mut attempt, _owner) = execution.start_http().unwrap();
            for submitted in 0..=limit {
                let error = attempt
                    .take()
                    .unwrap()
                    .commit("h2")
                    .unwrap()
                    .submit(|| Err::<(), _>(Error::Http("backend refused enqueue".into())))
                    .unwrap_err();
                assert_eq!(execution.attempt_counts(), (submitted + 1, submitted, 0));
                if submitted < limit {
                    attempt = attempt.recover("enqueue_failure").unwrap();
                } else {
                    assert!(attempt.recover("enqueue_failure").is_none());
                    guard.finish_error(&error);
                }
            }
            assert_eq!(execution.attempt_counts(), (limit + 1, limit, 0));
            let summary = execution.snapshot_summary();
            assert_eq!(summary.outcome(), AttemptOutcome::Failed);
            assert_eq!(
                summary.denial_reason(),
                Some(AttemptDenialReason::ExtraHttpLimit)
            );
            assert_count_bound(&execution);
        }
    }

    #[test]
    fn normal_redirects_do_not_consume_extra_allowance() {
        for limit in [0, 1, 3] {
            let (execution, _guard) = limited_execution(limit);
            let (mut attempt, owner) = execution.start_http().unwrap();
            commit(&attempt);
            for _ in 0..limit {
                attempt = attempt.recover("connection_closed").unwrap();
                commit(&attempt);
            }
            for redirects in 1..=3 {
                attempt = owner.redirect().unwrap();
                assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Normal);
                commit(&attempt);
                assert_eq!(
                    execution.attempt_counts(),
                    (1 + limit + redirects, limit, redirects)
                );
            }
            assert_eq!(execution.snapshot_summary().denial_reason(), None);
            assert!(attempt.recover("connection_closed").is_none());
            assert_eq!(execution.attempt_counts(), (4 + limit, limit, 3));
            assert_count_bound(&execution);
        }
    }

    #[test]
    fn capped_precommit_recovery_keeps_the_normal_entitlement() {
        for limit in [0, 1, 3] {
            let (execution, _guard) = limited_execution(limit);
            let (initial, _owner) = execution.start_http().unwrap();
            let ready_retry = initial.recover("connection_closed").unwrap();
            assert_eq!(ready_retry.generation, initial.generation);
            assert_eq!(execution.attempt_counts(), (0, 0, 0));
            drop(ready_retry.take().unwrap());
            let replacement = ready_retry.recover("connection_closed").unwrap();
            assert_ne!(replacement.generation, ready_retry.generation);
            assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Normal);
            assert_eq!(execution.attempt_counts(), (0, 0, 0));
            assert_eq!(execution.snapshot_summary().denial_reason(), None);
            commit(&replacement);
            assert_eq!(execution.attempt_counts(), (1, 0, 0));
            assert_count_bound(&execution);
        }
    }

    #[test]
    fn unresolved_limits_cannot_issue_http_authority() {
        let (execution, guard) = RequestExecution::with_limits(RequestTimeout::default(), None);
        let error = execution.start_http().err().unwrap();
        assert!(matches!(error, Error::InvalidConfig(_)));
        assert!(execution.inner.state.lock().current.is_none());
        assert_eq!(execution.attempt_counts(), (0, 0, 0));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::InvalidConfiguration)
        );
        guard.finish_error(&error);
        assert_eq!(
            execution.snapshot_summary().outcome(),
            AttemptOutcome::Failed
        );
        assert_eq!(execution.snapshot_summary().effective_limits(), None);
    }

    #[test]
    fn counter_exhaustion_remains_the_terminal_reason_before_reservation() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, owner) = execution.start_http().unwrap();
        execution.inner.state.lock().recoveries = u64::MAX;
        let before = authority_snapshot(&execution);
        assert!(owner.recover("overflow", None).is_none());
        for _ in 0..2 {
            assert!(attempt.take().is_err());
            assert!(owner.recover("retry_after_overflow", None).is_none());
            assert_eq!(authority_snapshot(&execution), before);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
        }
    }

    #[tokio::test]
    async fn retained_children_lose_authority_when_root_is_cancelled() {
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, owner) = execution.start_http().unwrap();
        let retained = execution.clone();
        let connection = execution.connection();
        let root_attempt = attempt.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let root = tokio::spawn(async move {
            let mut guard = guard;
            guard
                .run(async move {
                    commit(&root_attempt);
                    started.send(()).unwrap();
                    std::future::pending::<Result<()>>().await
                })
                .await
        });
        ready.await.unwrap();
        let child = retained.clone();
        let pending =
            tokio::spawn(async move { child.run(std::future::pending::<Result<()>>()).await });
        root.abort();
        assert!(root.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(attempt.take().is_err());
        assert!(owner.recover("connection_closed", None).is_none());
        assert!(retained.start_http().is_err());
        assert!(!connection.consume_tai_budget());
        assert_eq!(retained.snapshot(), (1, 0));
        assert_count_bound(&retained);
    }

    #[test]
    fn stop_notifications_cover_unpolled_registered_and_late_children() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake, Waker};

        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut unpolled = std::pin::pin!(execution.inner.stopped());
        let mut first = std::pin::pin!(execution.inner.stopped());
        let mut second = std::pin::pin!(execution.inner.stopped());
        let mut abandoned = Box::pin(execution.inner.stopped());
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert!(second.as_mut().poll(&mut context).is_pending());
        assert!(abandoned.as_mut().poll(&mut context).is_pending());
        drop(abandoned);
        drop(guard);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        assert!(unpolled.as_mut().poll(&mut context).is_ready());
        assert!(first.as_mut().poll(&mut context).is_ready());
        assert!(second.as_mut().poll(&mut context).is_ready());
        assert!(std::pin::pin!(execution.inner.stopped())
            .as_mut()
            .poll(&mut context)
            .is_ready());
    }

    #[tokio::test(start_paused = true)]
    async fn root_workflow_preserves_the_original_deadline() {
        let duration = std::time::Duration::from_secs(10);
        let (execution, mut guard) = RequestExecution::new(RequestTimeout::new(Some(duration)));
        let (attempt, _) = execution.start_http().unwrap();
        tokio::time::advance(std::time::Duration::from_secs(7)).await;
        let started = tokio::time::Instant::now();
        let error = guard
            .run(std::future::pending::<Result<()>>())
            .await
            .unwrap_err();
        assert!(error.is_timeout());
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(3));
        guard.finish_error(&error);
        assert!(attempt.take().is_err());
        assert_eq!(execution.snapshot(), (0, 0));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::Deadline)
        );
    }

    #[test]
    fn publication_revokes_authority_without_losing_counts() {
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, owner) = execution.start_http().unwrap();
        commit(&attempt);
        guard.publish().unwrap();
        assert!(execution.ensure_active().is_err());
        assert!(attempt.take().is_err());
        assert!(owner.recover("application_status", None).is_none());
        assert!(owner.redirect().is_err());
        assert_eq!(execution.snapshot(), (1, 0));
        assert_count_bound(&execution);
    }

    #[tokio::test]
    async fn concurrent_roots_and_nested_calls_keep_independent_counts() {
        let (outer, _guard) = RequestExecution::new(RequestTimeout::default());
        let (outer_attempt, outer_owner) = outer.start_http().unwrap();
        commit(&outer_attempt);
        let mut requests = Vec::new();
        for expected in 1..=8 {
            requests.push(tokio::spawn(async move {
                let (execution, guard) = RequestExecution::new(RequestTimeout::default());
                let (mut attempt, owner) = execution.start_http().unwrap();
                for index in 0..expected {
                    let child = attempt.clone();
                    commit(&child);
                    if index + 1 < expected {
                        attempt = owner.redirect().unwrap();
                    }
                    tokio::task::yield_now().await;
                }
                guard.publish().unwrap();
                assert_eq!(execution.snapshot(), (expected, 0));
                assert_eq!(execution.attempt_counts(), (expected, 0, expected - 1));
                assert!(attempt.take().is_err());
                assert_count_bound(&execution);
            }));
        }
        for request in requests {
            request.await.unwrap();
        }
        assert_eq!(outer.snapshot(), (1, 0));
        commit(&outer_owner.redirect().unwrap());
        assert_eq!(outer.snapshot(), (2, 0));
        assert_count_bound(&outer);
    }

    #[test]
    fn duplicate_take_and_abandoned_permit_do_not_create_submissions() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, owner) = execution.start_http().unwrap();
        let cloned = attempt.clone();
        let permit = attempt.take().unwrap();
        assert!(cloned.take().is_err());
        assert!(attempt.recover("while_reserved").is_none());
        assert!(owner.recover("while_reserved", None).is_none());
        assert_eq!(execution.snapshot(), (0, 0));
        drop(permit);
        assert!(attempt.take().is_err());
        assert_eq!(execution.attempt_counts(), (0, 0, 0));
        let successor = attempt.recover("abandoned_preparation").unwrap();
        assert_ne!(successor.generation, attempt.generation);
        assert!(cloned.take().is_err());
        commit(&successor);
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
        assert_count_bound(&execution);
    }

    #[test]
    fn stale_permit_cleanup_cannot_release_a_successor_reservation() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        drop(attempt.take().unwrap());
        // Exercise delayed predecessor cleanup after a new generation owns the slot.
        let stale = HttpPermit {
            attempt: attempt.clone(),
            committed: false,
        };
        let successor = attempt.recover("preparation_failed").unwrap();
        let permit = successor.take().unwrap();
        let before = authority_snapshot(&execution);
        drop(stale);
        assert_eq!(authority_snapshot(&execution), before);
        assert!(successor.take().is_err());
        assert!(permit.commit("h2").unwrap().submit(|| true));
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
    }

    #[test]
    fn initial_and_redirect_entitlements_are_issued_only_once() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        assert!(execution.start_http().is_err());
        assert!(owner.redirect().is_err());
        let permit = initial.take().unwrap();
        assert!(owner.redirect().is_err());
        assert!(permit.commit("h2").unwrap().submit(|| true));
        let redirect = owner.redirect().unwrap();
        assert!(owner.redirect().is_err());
        assert!(initial.take().is_err());
        commit(&redirect);
        assert!(execution.start_http().is_err());
        assert_eq!(execution.attempt_counts(), (2, 0, 1));
        assert_count_bound(&execution);
    }

    #[test]
    fn committed_attempts_remain_charged_when_backend_submission_fails() {
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let result = attempt
            .take()
            .unwrap()
            .commit("h2")
            .unwrap()
            .submit(|| Err::<(), _>(Error::Http("backend refused enqueue".into())));
        assert!(result.is_err());
        assert_eq!(execution.attempt_counts(), (1, 0, 0));
        let replacement = attempt.recover("enqueue_failure").unwrap();
        let result = replacement
            .take()
            .unwrap()
            .commit("h2")
            .unwrap()
            .submit(|| Err::<(), _>(Error::Http("backend refused replacement".into())));
        assert!(result.is_err());
        drop(guard);
        assert_eq!(execution.attempt_counts(), (2, 1, 0));
        assert_count_bound(&execution);
    }

    #[test]
    fn cancelled_root_invalidates_a_live_permit_before_commit() {
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, owner) = execution.start_http().unwrap();
        let permit = attempt.take().unwrap();
        drop(guard);
        assert!(permit.commit("h2").is_err());
        assert!(attempt.take().is_err());
        assert!(owner.recover("cancelled", None).is_none());
        assert_eq!(execution.attempt_counts(), (0, 0, 0));
        assert_eq!(execution.snapshot(), (0, 0));
    }

    #[test]
    fn an_unsubmitted_redirect_hop_preserves_its_normal_entitlement() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        commit(&initial);
        let redirect = owner.redirect().unwrap();
        let hop_owner = owner.hop_owner();
        drop(redirect.take().unwrap());
        let replacement = hop_owner.recover("pre_submit_failure", None).unwrap();
        assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Normal);
        commit(&replacement);
        assert_eq!(execution.attempt_counts(), (2, 0, 1));
        assert_count_bound(&execution);
    }

    #[test]
    fn application_restart_after_an_earlier_hop_stays_extra_until_submission() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        let original_start = owner.submissions();
        commit(&initial);
        let unused_redirect = owner.redirect().unwrap();
        let restart = owner
            .recover("application_error", Some(original_start))
            .unwrap();
        assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Extra);
        assert!(unused_redirect.take().is_err());
        let restart_start = owner.submissions();
        drop(restart.take().unwrap());
        let retried = owner
            .recover("application_error", Some(restart_start))
            .unwrap();
        assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Extra);
        assert_eq!(execution.attempt_counts(), (1, 0, 1));
        commit(&retried);
        assert_eq!(execution.attempt_counts(), (2, 1, 1));
        let followed = owner.redirect().unwrap();
        assert!(execution.inner.state.lock().current.unwrap().kind == AttemptKind::Normal);
        commit(&followed);
        assert_eq!(execution.attempt_counts(), (3, 1, 2));
        assert_count_bound(&execution);
    }

    #[test]
    fn commit_counter_overflow_does_not_partially_charge_attempts() {
        for overflow_extra in [false, true] {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (initial, _owner) = execution.start_http().unwrap();
            let attempt = if overflow_extra {
                commit(&initial);
                initial.recover("replacement").unwrap()
            } else {
                initial
            };
            let permit = attempt.take().unwrap();
            {
                let mut state = execution.inner.state.lock();
                if overflow_extra {
                    state.extra_http = u64::MAX;
                } else {
                    state.http_attempts = u64::MAX;
                }
            }
            let mut expected = authority_snapshot(&execution);
            assert!(permit.commit("h2").is_err());
            expected.status = AttemptStatus::Released as u8;
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
            assert!(attempt.recover("retry_after_overflow").is_none());
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
        }
    }

    #[test]
    fn recovery_overflow_preserves_counters_generation_and_entitlement() {
        for overflow_generation in [false, true] {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (attempt, owner) = execution.start_http().unwrap();
            drop(attempt.take().unwrap());
            {
                let mut state = execution.inner.state.lock();
                if overflow_generation {
                    state.current.as_mut().unwrap().generation = u64::MAX;
                } else {
                    state.recoveries = u64::MAX;
                }
            }
            let expected = authority_snapshot(&execution);
            assert!(owner.recover("overflow", None).is_none());
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
            assert!(owner.recover("retry_after_overflow", None).is_none());
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
        }
    }

    #[test]
    fn redirect_overflow_preserves_counters_generation_and_entitlement() {
        for overflow_generation in [false, true] {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (attempt, owner) = execution.start_http().unwrap();
            commit(&attempt);
            {
                let mut state = execution.inner.state.lock();
                if overflow_generation {
                    state.current.as_mut().unwrap().generation = u64::MAX;
                } else {
                    state.redirects = u64::MAX;
                }
            }
            let expected = authority_snapshot(&execution);
            assert!(owner.redirect().is_err());
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
            assert!(owner.redirect().is_err());
            assert_eq!(authority_snapshot(&execution), expected);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::CounterExhausted)
            );
        }
    }

    #[tokio::test]
    async fn deadline_denies_initial_authority_commit_and_publication() {
        let (execution, guard) =
            RequestExecution::new(RequestTimeout::new(Some(std::time::Duration::ZERO)));
        assert!(execution.ensure_active().unwrap_err().is_timeout());
        assert!(execution.start_http().err().unwrap().is_timeout());
        // Model a reservation predating expiry without wall-clock sleeps.
        execution.inner.state.lock().current = Some(AttemptState {
            generation: 1,
            kind: AttemptKind::Normal,
            status: AttemptStatus::Reserved,
        });
        let permit = HttpPermit {
            attempt: HttpAttempt {
                execution: execution.clone(),
                generation: 1,
            },
            committed: false,
        };
        assert!(permit.commit("h2").err().unwrap().is_timeout());
        assert!(guard.publish().unwrap_err().is_timeout());
        assert_eq!(execution.snapshot(), (0, 0));
    }
}
