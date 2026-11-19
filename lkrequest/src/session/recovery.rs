//! Recovery decisions for the compatible request pipeline.
//!
//! Local retry windows retain their existing scopes. Explicit request execution
//! owns authorization and accounting across redirects and retries.

use std::time::Duration;

use crate::attempts::AttemptDenialReason;
use crate::body::RequestBody;
use crate::error::{Error, Result};
use crate::retry::RetryPolicy;

use super::execution::{HttpAttempt, RecoveryOwner};
#[cfg(feature = "quic-h3")]
use super::pipeline::ProtocolDecision;
use super::Idempotency;

#[derive(Clone, Copy)]
pub(crate) struct ReplayFacts<'a> {
    method: &'a http::Method,
    idempotency: Idempotency,
    body: Option<&'a RequestBody>,
}

impl<'a> ReplayFacts<'a> {
    pub fn new(
        method: &'a http::Method,
        idempotency: Idempotency,
        body: Option<&'a RequestBody>,
    ) -> Self {
        Self {
            method,
            idempotency,
            body,
        }
    }

    fn body_replayable(self) -> bool {
        self.body.is_none_or(RequestBody::can_replay)
    }

    fn error_replay_denial(self, error: &Error) -> Option<AttemptDenialReason> {
        if !self.body_replayable() {
            Some(AttemptDenialReason::BodyUnavailable)
        } else if !crate::retry::retry_is_replay_safe(self.method, self.idempotency, error) {
            Some(AttemptDenialReason::ReplayDenied)
        } else {
            None
        }
    }

    #[cfg(feature = "quic-h3")]
    pub fn early_data_allowed(self) -> bool {
        super::can_send_early_data(self.method, self.idempotency)
            && !self.body.is_some_and(RequestBody::is_streaming)
    }
}

pub(super) fn connection_retry(
    available: bool,
    enabled: bool,
    facts: ReplayFacts<'_>,
    error: &Error,
    attempt: &HttpAttempt,
) -> Option<HttpAttempt> {
    if !available || !enabled || !error.is_connection_closed() {
        return None;
    }
    if let Some(reason) = facts.error_replay_denial(error) {
        attempt.record_denial(reason);
        return None;
    }
    attempt.recover("connection_closed")
}

pub(super) fn h2_fallback(
    enabled: bool,
    facts: ReplayFacts<'_>,
    error: &Error,
    attempt: &HttpAttempt,
) -> Option<HttpAttempt> {
    if !enabled || !(matches!(error, Error::H2(_)) || error.is_connection_closed()) {
        return None;
    }
    if let Some(reason) = facts.error_replay_denial(error) {
        attempt.record_denial(reason);
        return None;
    }
    attempt.recover("h2_to_h1")
}

pub(super) fn reconstruction(
    facts: ReplayFacts<'_>,
    attempt: &HttpAttempt,
    kind: &'static str,
) -> Option<HttpAttempt> {
    if !facts.body_replayable() {
        attempt.record_denial(AttemptDenialReason::BodyUnavailable);
        return None;
    }
    attempt.recover_reconstruction(
        kind,
        super::can_send_early_data(facts.method, facts.idempotency),
    )
}

pub(crate) struct ApplicationRetry {
    pub delay: Duration,
    pub attempt: HttpAttempt,
}

pub(crate) struct ApplicationRecovery {
    owner: RecoveryOwner,
    submissions_at_start: u64,
    callback_attempt: u32,
    replay_safe: bool,
    policy_allowed: bool,
}

impl ApplicationRecovery {
    pub fn new(owner: RecoveryOwner) -> Self {
        let submissions_at_start = owner.submissions();
        Self {
            owner,
            submissions_at_start,
            callback_attempt: 0,
            replay_safe: true,
            policy_allowed: true,
        }
    }

    pub fn start_attempt(&mut self) {
        self.submissions_at_start = self.owner.submissions();
        self.replay_safe = true;
        self.policy_allowed = true;
    }

    pub fn stop_on_connect_denial(&mut self, error: &Error) {
        if let Some(reason) = error.connect_denial_reason() {
            self.policy_allowed = false;
            self.owner.record_denial(reason);
        }
    }

    #[cfg(feature = "quic-h3")]
    pub fn hop_owner(&self) -> RecoveryOwner {
        self.owner.hop_owner()
    }

    pub fn redirect_attempt(&self) -> Result<HttpAttempt> {
        self.owner.redirect()
    }

    pub fn completed_hop(&mut self, method: &http::Method, idempotency: Idempotency) {
        self.replay_safe &= super::can_send_early_data(method, idempotency);
    }

    pub fn retry_status(
        &mut self,
        policy: &dyn RetryPolicy,
        facts: ReplayFacts<'_>,
        status: http::StatusCode,
    ) -> Option<ApplicationRetry> {
        if self.owner.is_terminal_denied()
            || !self.policy_allowed
            || !crate::retry::is_retryable_status(status)
        {
            return None;
        }
        if !facts.body_replayable() {
            self.owner
                .record_denial(AttemptDenialReason::BodyUnavailable);
            return None;
        }
        self.callback_attempt = self.callback_attempt.checked_add(1)?;
        // Compatible mode invokes the callback before semantic replay checks.
        let delay = policy.should_retry(self.callback_attempt, None, Some(status))?;
        if !crate::retry::status_retry_is_replay_safe(facts.method, facts.idempotency, status) {
            self.owner.record_denial(AttemptDenialReason::ReplayDenied);
            tracing::debug!(method = %facts.method, status = status.as_u16(), "http.retry_on_status_skipped_not_replay_safe");
            return None;
        }
        let attempt = self
            .owner
            .recover("application_status", Some(self.submissions_at_start))?;
        tracing::warn!(
            attempt = self.callback_attempt,
            status = status.as_u16(),
            delay_ms = delay.as_millis() as u64,
            "http.retry_on_status"
        );
        Some(ApplicationRetry { delay, attempt })
    }

    pub fn retry_error(
        &mut self,
        policy: &dyn RetryPolicy,
        facts: ReplayFacts<'_>,
        error: &Error,
    ) -> Option<ApplicationRetry> {
        if self.owner.is_terminal_denied()
            || !self.policy_allowed
            || error.is_connect_attempt_denied()
        {
            return None;
        }
        self.callback_attempt = self.callback_attempt.checked_add(1)?;
        let delay = policy.should_retry(self.callback_attempt, Some(error), None)?;
        let denial = facts
            .error_replay_denial(error)
            .or_else(|| (!self.replay_safe).then_some(AttemptDenialReason::ReplayDenied));
        if let Some(reason) = denial {
            self.owner.record_denial(reason);
            tracing::warn!(attempt = self.callback_attempt, error = %error, method = %facts.method, "http.retry_skipped_non_idempotent");
            return None;
        }
        let attempt = self
            .owner
            .recover("application_error", Some(self.submissions_at_start))?;
        tracing::warn!(attempt = self.callback_attempt, error = %error, delay_ms = delay.as_millis() as u64, "http.retry_on_error");
        Some(ApplicationRetry { delay, attempt })
    }
}

#[cfg(feature = "quic-h3")]
pub(super) struct ProtocolRecovery {
    owner: RecoveryOwner,
    retries: u32,
}

#[cfg(feature = "quic-h3")]
pub(super) struct ProtocolRetry {
    pub route: ProtocolDecision,
    pub attempt: HttpAttempt,
}

#[cfg(feature = "quic-h3")]
impl ProtocolRecovery {
    pub fn new(owner: RecoveryOwner) -> Self {
        Self { owner, retries: 0 }
    }

    pub fn retry(
        &mut self,
        mode: crate::retry::H3RetryMode,
        error: &Error,
        facts: ReplayFacts<'_>,
        route: Option<ProtocolDecision>,
        application: Option<&mut ApplicationRecovery>,
    ) -> Option<ProtocolRetry> {
        if error.is_connect_attempt_denied() || !crate::retry::chrome_h3_owns_error(mode, error) {
            return None;
        }
        if let Some(application) = application {
            application.policy_allowed = false;
        }
        if self.owner.is_terminal_denied() {
            return None;
        }
        if !crate::retry::chrome_h3_can_retry(error, facts.idempotency, facts.body, self.retries) {
            if error.h3_request_context().is_some_and(|context| {
                context.stage == crate::error::H3ResponseStage::AwaitingResponse
            }) {
                let reason = if !facts.body_replayable() {
                    AttemptDenialReason::BodyUnavailable
                } else if facts.idempotency == Idempotency::NotIdempotent
                    || facts.body.is_some_and(RequestBody::is_streaming)
                {
                    AttemptDenialReason::ReplayDenied
                } else if self.retries >= crate::retry::MAX_CHROME_H3_RETRIES {
                    AttemptDenialReason::ProtocolOwnerExhausted
                } else {
                    return None;
                };
                self.owner.record_denial(reason);
            }
            return None;
        }
        let route = route?;
        let attempt = self.owner.recover("h3_protocol", None)?;
        self.retries += 1;
        tracing::debug!(
            retry = self.retries,
            protocol = route.as_str(),
            "h3.chrome_protocol_error_retry"
        );
        Some(ProtocolRetry { route, attempt })
    }
}

#[derive(Clone)]
pub(super) struct RequestRecovery {
    pub attempt: HttpAttempt,
    pub retry_pooled: bool,
    #[cfg(feature = "quic-h3")]
    pub race_send_gates: Vec<RaceSendGate>,
}

impl RequestRecovery {
    pub fn next_attempt(&self) -> Self {
        let mut next = self.clone();
        next.retry_pooled = false;
        next
    }

    pub fn with_attempt(&self, attempt: HttpAttempt) -> Self {
        let mut next = self.next_attempt();
        next.attempt = attempt;
        next
    }
}

#[cfg(feature = "quic-h3")]
#[derive(Clone)]
pub(crate) struct RaceSendGate {
    selected: tokio::sync::watch::Sender<Option<ProtocolDecision>>,
    branch: ProtocolDecision,
}

#[cfg(feature = "quic-h3")]
impl RaceSendGate {
    pub(crate) fn pair() -> (
        Self,
        Self,
        tokio::sync::watch::Receiver<Option<ProtocolDecision>>,
    ) {
        let (selected, receiver) = tokio::sync::watch::channel(None);
        (
            Self {
                selected: selected.clone(),
                branch: ProtocolDecision::Quic,
            },
            Self {
                selected,
                branch: ProtocolDecision::Tcp,
            },
            receiver,
        )
    }

    /// Claim after acquisition, before HTTP enqueue or invoking an upload body.
    pub(crate) async fn acquired(&self) {
        self.selected.send_if_modified(|selected| {
            if selected.is_none() {
                *selected = Some(self.branch);
                true
            } else {
                false
            }
        });
        let won = *self.selected.borrow() == Some(self.branch);
        if !won {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempts::{AttemptLimitScope, AttemptLimits};
    use crate::error::{ConnectionClosedKind, ConnectionPhase};
    use crate::session::execution::RequestExecution;
    use crate::timeout::RequestTimeout;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct ObservedPolicy(Mutex<Vec<u32>>, Duration);

    impl RetryPolicy for ObservedPolicy {
        fn should_retry(
            &self,
            attempt: u32,
            _: Option<&Error>,
            _: Option<http::StatusCode>,
        ) -> Option<Duration> {
            self.0.lock().unwrap().push(attempt);
            Some(self.1)
        }
    }

    fn closed() -> Error {
        Error::ConnectionClosed {
            phase: ConnectionPhase::HttpRequest,
            kind: ConnectionClosedKind::Generic,
            message: "peer closed after request".into(),
        }
    }

    fn commit(attempt: &HttpAttempt, protocol: &'static str) {
        assert!(attempt
            .take()
            .unwrap()
            .commit(protocol)
            .unwrap()
            .submit(|| true));
    }

    #[test]
    fn retries_and_redirects_share_accounting_but_not_callback_numbers() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let policy = ObservedPolicy::default();
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        application.start_attempt();
        commit(&initial, "h2");
        application.completed_hop(&http::Method::GET, Idempotency::Default);
        commit(&application.redirect_attempt().unwrap(), "h2");
        let retry = application.retry_error(&policy, facts, &closed()).unwrap();
        assert_eq!(retry.delay, Duration::ZERO);
        application.start_attempt();
        commit(&retry.attempt, "h3");
        assert!(application
            .retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
            .is_some());
        assert_eq!(execution.snapshot(), (3, 2));
        assert_eq!(*policy.0.lock().unwrap(), vec![1, 2]);
        let (independent, _independent_guard) = RequestExecution::new(RequestTimeout::default());
        assert_eq!(independent.snapshot(), (0, 0));
    }

    #[test]
    fn compatible_callback_observes_denied_unsafe_retries() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (_, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let policy = ObservedPolicy::default();
        let post = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
        assert!(application.retry_error(&policy, post, &closed()).is_none());
        assert!(application
            .retry_status(&policy, post, http::StatusCode::BAD_GATEWAY)
            .is_none());
        assert_eq!(*policy.0.lock().unwrap(), vec![1, 2]);
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ReplayDenied)
        );
    }

    #[test]
    fn application_cap_denial_returns_no_delay_and_preserves_callback_order() {
        for retry_status in [false, true] {
            let limits = AttemptLimits::default()
                .with_extra_http_attempts(1)
                .resolve(None, AttemptLimitScope::Client)
                .unwrap();
            let (execution, guard) =
                RequestExecution::with_limits(RequestTimeout::default(), Some(limits));
            let (initial, owner) = execution.start_http().unwrap();
            let mut application = ApplicationRecovery::new(owner);
            let policy = ObservedPolicy(Mutex::new(Vec::new()), Duration::from_secs(3600));
            let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
            let retry = |application: &mut ApplicationRecovery| {
                if retry_status {
                    application.retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
                } else {
                    application.retry_error(&policy, facts, &closed())
                }
            };
            application.start_attempt();
            commit(&initial, "h2");
            let approved = retry(&mut application).unwrap();
            assert_eq!(approved.delay, Duration::from_secs(3600));
            application.start_attempt();
            commit(&approved.attempt, "h2");
            assert!(retry(&mut application).is_none());
            assert_eq!(*policy.0.lock().unwrap(), vec![1, 2]);
            assert!(retry(&mut application).is_none());
            assert_eq!(*policy.0.lock().unwrap(), vec![1, 2]);
            assert_eq!(execution.snapshot(), (2, 1));
            assert_eq!(execution.snapshot_summary().extra_http_submissions(), 1);
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::ExtraHttpLimit)
            );
            execution.ensure_active().unwrap();
            guard.publish().unwrap();
        }
    }

    #[test]
    fn inner_cap_denial_blocks_outer_callbacks_without_stopping_publication() {
        for recovery_kind in ["connection_closed", "h2_to_h1", "reconstruction"] {
            let limits = AttemptLimits::default()
                .with_extra_http_attempts(0)
                .resolve(None, AttemptLimitScope::Client)
                .unwrap();
            let (execution, guard) =
                RequestExecution::with_limits(RequestTimeout::default(), Some(limits));
            let (initial, owner) = execution.start_http().unwrap();
            let mut application = ApplicationRecovery::new(owner);
            let policy = ObservedPolicy::default();
            let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
            application.start_attempt();
            commit(&initial, "h2");
            let denied = match recovery_kind {
                "connection_closed" => connection_retry(true, true, facts, &closed(), &initial),
                "h2_to_h1" => h2_fallback(true, facts, &closed(), &initial),
                _ => reconstruction(facts, &initial, "early_data_reconstruction"),
            };
            assert!(denied.is_none());
            application.start_attempt();
            assert!(application.retry_error(&policy, facts, &closed()).is_none());
            assert!(application
                .retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
                .is_none());
            assert!(policy.0.lock().unwrap().is_empty());
            assert_eq!(execution.snapshot(), (1, 0));
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::ExtraHttpLimit)
            );
            execution.ensure_active().unwrap();
            guard.publish().unwrap();
        }
    }

    #[test]
    fn unavailable_body_preserves_existing_application_callback_timing() {
        for retry_status in [false, true] {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (_, owner) = execution.start_http().unwrap();
            let mut application = ApplicationRecovery::new(owner);
            let policy = ObservedPolicy::default();
            let body = RequestBody::reader(tokio::io::empty(), None);
            let _upload = body.clone().into_upload().unwrap();
            let facts = ReplayFacts::new(&http::Method::POST, Idempotency::Default, Some(&body));
            if retry_status {
                assert!(application
                    .retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
                    .is_none());
                assert!(policy.0.lock().unwrap().is_empty());
            } else {
                assert!(application.retry_error(&policy, facts, &closed()).is_none());
                assert_eq!(*policy.0.lock().unwrap(), vec![1]);
            }
            assert_eq!(
                execution.snapshot_summary().denial_reason(),
                Some(AttemptDenialReason::BodyUnavailable)
            );
        }
    }

    #[test]
    fn disabled_or_ineligible_application_retries_do_not_record_denials() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (_, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let policy = crate::retry::FixedInterval::new(0, Duration::ZERO);
        let facts = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
        assert!(application.retry_error(&policy, facts, &closed()).is_none());
        assert!(application
            .retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
            .is_none());
        assert!(application
            .retry_status(&ObservedPolicy::default(), facts, http::StatusCode::OK)
            .is_none());
        assert_eq!(execution.snapshot_summary().denial_reason(), None);
    }

    #[test]
    fn completed_unsafe_hop_blocks_error_replay_even_if_later_error_was_pre_send() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let policy = ObservedPolicy::default();
        application.start_attempt();
        commit(&initial, "h2");
        application.completed_hop(&http::Method::POST, Idempotency::NotIdempotent);
        let _redirect = application.redirect_attempt().unwrap();
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        let error = Error::connection(ConnectionPhase::TcpConnect, "refused before send", None);
        assert!(application.retry_error(&policy, facts, &error).is_none());
        assert_eq!(*policy.0.lock().unwrap(), vec![1]);
        assert_eq!(execution.snapshot(), (1, 0));
    }

    #[test]
    fn denied_connection_recovery_does_not_consume_authorization() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let get = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        let post = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
        assert!(connection_retry(true, false, get, &closed(), &attempt).is_none());
        assert!(connection_retry(false, true, get, &closed(), &attempt).is_none());
        assert!(
            connection_retry(true, true, post, &Error::Http("unrelated".into()), &attempt)
                .is_none()
        );
        assert_eq!(execution.snapshot_summary().denial_reason(), None);
        assert!(connection_retry(true, true, post, &closed(), &attempt).is_none());
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ReplayDenied)
        );
        assert_eq!(execution.snapshot(), (0, 0));
        assert!(connection_retry(true, true, get, &closed(), &attempt).is_some());
        assert_eq!(execution.snapshot(), (0, 1));
    }

    #[test]
    fn transport_recovery_distinguishes_body_and_semantic_denials() {
        for connection in [false, true] {
            for consumed in [false, true] {
                let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
                let (attempt, _owner) = execution.start_http().unwrap();
                let body = RequestBody::reader(tokio::io::empty(), None);
                let _upload = consumed.then(|| body.clone().into_upload().unwrap());
                let facts =
                    ReplayFacts::new(&http::Method::POST, Idempotency::Default, Some(&body));
                let denied = if connection {
                    connection_retry(true, true, facts, &closed(), &attempt)
                } else {
                    h2_fallback(true, facts, &closed(), &attempt)
                };
                assert!(denied.is_none());
                assert_eq!(
                    execution.snapshot_summary().denial_reason(),
                    Some(if consumed {
                        AttemptDenialReason::BodyUnavailable
                    } else {
                        AttemptDenialReason::ReplayDenied
                    })
                );
                assert_eq!(execution.snapshot(), (0, 0));
            }
        }
    }

    #[test]
    fn transport_recovery_replaces_only_an_authorized_attempt() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let recovery = RequestRecovery {
            attempt: attempt.clone(),
            retry_pooled: true,
            #[cfg(feature = "quic-h3")]
            race_send_gates: Vec::new(),
        };
        let ready_retry = recovery.next_attempt();
        assert!(!ready_retry.retry_pooled);
        commit(&ready_retry.attempt, "h2");
        assert!(attempt.take().is_err());

        let get = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        assert!(h2_fallback(false, get, &closed(), &ready_retry.attempt).is_none());
        let approved = h2_fallback(true, get, &closed(), &ready_retry.attempt).unwrap();
        let fallback = ready_retry.with_attempt(approved);
        assert!(!fallback.retry_pooled);
        commit(&fallback.attempt, "http/1.1");
        assert!(ready_retry.attempt.take().is_err());
        assert_eq!(execution.snapshot(), (2, 1));
    }

    #[test]
    fn reconstruction_allows_unsafe_method_only_before_submission() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let post = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
        let fallback = reconstruction(post, &attempt, "quic_handshake_fallback").unwrap();
        commit(&fallback, "http/1.1");
        assert!(reconstruction(post, &fallback, "early_rebuild").is_none());
        assert_eq!(execution.snapshot(), (1, 1));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ReplayDenied)
        );

        let idempotent = ReplayFacts::new(&http::Method::POST, Idempotency::Idempotent, None);
        let replacement = reconstruction(idempotent, &fallback, "early_rebuild").unwrap();
        commit(&replacement, "http/1.1");
        assert!(reconstruction(idempotent, &fallback, "stale_rebuild").is_none());
        assert_eq!(execution.snapshot(), (2, 2));
    }

    #[test]
    fn reconstruction_never_reclaims_a_consumed_upload() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let body = RequestBody::reader(tokio::io::empty(), None);
        let _upload = body.clone().into_upload().unwrap();
        let get = ReplayFacts::new(&http::Method::GET, Idempotency::Default, Some(&body));
        assert!(reconstruction(get, &attempt, "before_submit_fallback").is_none());
        assert_eq!(execution.snapshot(), (0, 0));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::BodyUnavailable)
        );
    }

    #[test]
    fn reconstruction_racing_unsafe_submission_cannot_grant_a_second_attempt() {
        for _ in 0..64 {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (attempt, _owner) = execution.start_http().unwrap();
            let post = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
            let barrier = std::sync::Barrier::new(2);
            let replacement = std::thread::scope(|scope| {
                let sender = scope.spawn(|| {
                    barrier.wait();
                    commit(&attempt, "http/1.1");
                });
                barrier.wait();
                let replacement = reconstruction(post, &attempt, "concurrent_fallback");
                sender.join().unwrap();
                replacement
            });
            if let Some(replacement) = replacement {
                assert!(
                    replacement.take().is_err(),
                    "pre-submit recovery must share the submission that won the race"
                );
            }
            assert_eq!(execution.snapshot().0, 1);
        }
    }

    #[test]
    fn execution_denial_preserves_application_callback_order() {
        let (execution, guard) = RequestExecution::new(RequestTimeout::default());
        let (_, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let policy = ObservedPolicy::default();
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        drop(guard);
        assert!(application.retry_error(&policy, facts, &closed()).is_none());
        assert!(application
            .retry_status(&policy, facts, http::StatusCode::SERVICE_UNAVAILABLE)
            .is_none());
        assert_eq!(*policy.0.lock().unwrap(), vec![1, 2]);
        assert_eq!(execution.snapshot(), (0, 0));
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn a_losing_race_candidate_cannot_commit_an_http_attempt() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let (quic, tcp, _) = RaceSendGate::pair();
        let winner = async {
            quic.acquired().await;
            commit(&attempt, "h3");
        };
        let loser = async {
            tcp.acquired().await;
            commit(&attempt, "h2");
            panic!("losing branch acquired send authority");
        };
        tokio::select! {
            biased;
            _ = winner => {}
            _ = loser => unreachable!(),
        }
        assert_eq!(execution.snapshot(), (1, 0));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tcp.acquired())
                .await
                .is_err()
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn early_admission_does_not_require_connection_retry_permission() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (attempt, _owner) = execution.start_http().unwrap();
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        assert!(facts.early_data_allowed());
        assert!(connection_retry(true, false, facts, &closed(), &attempt).is_none());
    }

    #[cfg(feature = "quic-h3")]
    fn protocol_error() -> Error {
        Error::H3RequestContext(Box::new(crate::error::H3RequestContext {
            stage: crate::error::H3ResponseStage::AwaitingResponse,
            kind: crate::error::H3FailureKind::Protocol,
            backend_final_received: false,
            stopped_upload: None,
            connection_terminated: true,
            source: Box::new(Error::Http3Request("protocol error".into())),
        }))
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn protocol_owner_exhaustion_cannot_fall_through_to_application_retry() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (initial, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let mut protocol = ProtocolRecovery::new(application.hop_owner());
        let policy = ObservedPolicy::default();
        let facts = ReplayFacts::new(&http::Method::POST, Idempotency::Default, None);
        let error = protocol_error();
        commit(&initial, "h3");
        for expected in [
            Some(ProtocolDecision::Quic),
            Some(ProtocolDecision::Quic),
            None,
        ] {
            let retry = protocol.retry(
                crate::retry::H3RetryMode::Chrome155ProtocolErrors,
                &error,
                facts,
                Some(ProtocolDecision::Quic),
                Some(&mut application),
            );
            assert_eq!(retry.as_ref().map(|retry| retry.route), expected);
            if let Some(retry) = retry {
                commit(&retry.attempt, "h3");
            }
        }
        assert!(application.retry_error(&policy, facts, &error).is_none());
        assert!(policy.0.lock().unwrap().is_empty());
        assert_eq!(execution.snapshot(), (3, 2));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ProtocolOwnerExhausted)
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn disabled_or_ineligible_protocol_recovery_does_not_record_denials() {
        for case in 0..3 {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (_, owner) = execution.start_http().unwrap();
            let mut protocol = ProtocolRecovery::new(owner);
            let mut error = protocol_error();
            let mode = if case == 0 {
                crate::retry::H3RetryMode::Safe
            } else {
                crate::retry::H3RetryMode::Chrome155ProtocolErrors
            };
            if case == 1 {
                error = Error::Http("not a protocol failure".into());
            } else if case == 2 {
                let Error::H3RequestContext(context) = &mut error else {
                    unreachable!()
                };
                context.stage = crate::error::H3ResponseStage::ResponseBody;
            }
            let facts = ReplayFacts::new(&http::Method::POST, Idempotency::NotIdempotent, None);
            assert!(protocol
                .retry(mode, &error, facts, Some(ProtocolDecision::Quic), None)
                .is_none());
            assert_eq!(execution.snapshot_summary().denial_reason(), None);
            assert_eq!(execution.snapshot(), (0, 0));
        }
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn protocol_recovery_distinguishes_body_and_semantic_denials() {
        for (idempotency, streaming, consumed, expected) in [
            (
                Idempotency::NotIdempotent,
                false,
                false,
                AttemptDenialReason::ReplayDenied,
            ),
            (
                Idempotency::Idempotent,
                true,
                false,
                AttemptDenialReason::ReplayDenied,
            ),
            (
                Idempotency::NotIdempotent,
                true,
                true,
                AttemptDenialReason::BodyUnavailable,
            ),
        ] {
            let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
            let (_, owner) = execution.start_http().unwrap();
            let mut protocol = ProtocolRecovery::new(owner);
            let body = streaming.then(|| RequestBody::reader(tokio::io::empty(), None));
            let _upload = consumed.then(|| body.as_ref().unwrap().clone().into_upload().unwrap());
            let facts = ReplayFacts::new(&http::Method::POST, idempotency, body.as_ref());
            assert!(protocol
                .retry(
                    crate::retry::H3RetryMode::Chrome155ProtocolErrors,
                    &protocol_error(),
                    facts,
                    Some(ProtocolDecision::Quic),
                    None,
                )
                .is_none());
            assert_eq!(execution.snapshot_summary().denial_reason(), Some(expected));
            assert_eq!(execution.snapshot(), (0, 0));
        }
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn protocol_cap_denial_survives_outer_recovery_restart() {
        let limits = AttemptLimits::default()
            .with_extra_http_attempts(0)
            .resolve(None, AttemptLimitScope::Client)
            .unwrap();
        let (execution, guard) =
            RequestExecution::with_limits(RequestTimeout::default(), Some(limits));
        let (initial, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let mut protocol = ProtocolRecovery::new(application.hop_owner());
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        commit(&initial, "h3");
        for _ in 0..2 {
            assert!(protocol
                .retry(
                    crate::retry::H3RetryMode::Chrome155ProtocolErrors,
                    &protocol_error(),
                    facts,
                    Some(ProtocolDecision::Quic),
                    Some(&mut application),
                )
                .is_none());
            application.start_attempt();
            protocol = ProtocolRecovery::new(application.hop_owner());
        }
        let policy = ObservedPolicy::default();
        assert!(application.retry_error(&policy, facts, &closed()).is_none());
        assert!(policy.0.lock().unwrap().is_empty());
        assert_eq!(execution.snapshot(), (1, 0));
        assert_eq!(
            execution.snapshot_summary().denial_reason(),
            Some(AttemptDenialReason::ExtraHttpLimit)
        );
        guard.publish().unwrap();
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn rejected_protocol_route_still_owns_the_error() {
        let (execution, _guard) = RequestExecution::new(RequestTimeout::default());
        let (_, owner) = execution.start_http().unwrap();
        let mut application = ApplicationRecovery::new(owner);
        let mut protocol = ProtocolRecovery::new(application.hop_owner());
        let policy = ObservedPolicy::default();
        let facts = ReplayFacts::new(&http::Method::GET, Idempotency::Default, None);
        let error = protocol_error();
        assert!(protocol
            .retry(
                crate::retry::H3RetryMode::Chrome155ProtocolErrors,
                &error,
                facts,
                None,
                Some(&mut application),
            )
            .is_none());
        assert!(application.retry_error(&policy, facts, &error).is_none());
        assert!(policy.0.lock().unwrap().is_empty());
        assert_eq!(execution.snapshot_summary().denial_reason(), None);
    }
}
