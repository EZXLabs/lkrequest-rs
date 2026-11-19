//! Optional limits and bounded accounting for one logical request.

use crate::error::{Error, Result};

/// The configuration level that supplies an effective attempt limit.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptLimitScope {
    Client,
    Session,
    Request,
}

impl AttemptLimitScope {
    /// Stable name used in diagnostic output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Session => "session",
            Self::Request => "request",
        }
    }
}

/// Requested aggregate limits, separate from protocol and retry policy.
///
/// An unset client limit adds no aggregate ceiling. An unset session or request
/// limit inherits its parent's effective value. A finite child can only tighten
/// a finite parent; it cannot enable recovery forbidden by an existing policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptLimits {
    extra_http_attempts: Option<u64>,
    connect_attempts: Option<u64>,
}

impl AttemptLimits {
    /// Limit committed replacement HTTP submissions for one logical request.
    ///
    /// Zero permits initial and allowed redirect submissions but no extra HTTP
    /// submissions. Every `u64` value is finite, including `u64::MAX`.
    pub const fn with_extra_http_attempts(mut self, limit: u64) -> Self {
        self.extra_http_attempts = Some(limit);
        self
    }

    /// Clear this level's override. A child still inherits a finite parent.
    pub const fn without_extra_http_limit(mut self) -> Self {
        self.extra_http_attempts = None;
        self
    }

    /// The requested value, before inheritance or validation.
    pub const fn extra_http_attempts(self) -> Option<u64> {
        self.extra_http_attempts
    }

    /// Limit TCP and QUIC backend connection starts in this operation.
    /// Zero still permits pooled reuse and waiting for shared establishment.
    pub const fn with_connect_attempts(mut self, limit: u64) -> Self {
        self.connect_attempts = Some(limit);
        self
    }

    /// Clear this level's connection override, inheriting a finite parent.
    pub const fn without_connect_limit(mut self) -> Self {
        self.connect_attempts = None;
        self
    }

    /// Requested connection starts, before inheritance or validation.
    pub const fn connect_attempts(self) -> Option<u64> {
        self.connect_attempts
    }

    /// Resolve this configuration against its parent before starting I/O.
    ///
    /// Resolve the client with `parent: None`, then pass its effective limits to
    /// the session and the session's effective limits to the request. Equal
    /// values retain the ancestor's limiting scope. A larger finite child is an
    /// error, rather than a silently clamped value. Resolution never changes
    /// either input.
    pub fn resolve(
        self,
        parent: Option<&EffectiveAttemptLimits>,
        scope: AttemptLimitScope,
    ) -> Result<EffectiveAttemptLimits> {
        let inherited = parent.copied().unwrap_or_default();
        let resolve_limit = |requested: Option<u64>,
                             parent_limit: Option<u64>,
                             parent_scope: Option<AttemptLimitScope>,
                             name: &str| {
            let Some(requested) = requested else {
                return Ok((parent_limit, parent_scope));
            };
            if let Some(parent_limit) = parent_limit {
                if requested > parent_limit {
                    return Err(Error::InvalidConfig(format!(
                    "{} {name} attempt limit {requested} exceeds inherited limit {parent_limit}",
                    scope.as_str()
                )));
                }
                if requested == parent_limit {
                    return Ok((Some(parent_limit), parent_scope));
                }
            }
            Ok((Some(requested), Some(scope)))
        };
        let (extra_http_attempts, extra_http_scope) = resolve_limit(
            self.extra_http_attempts,
            inherited.extra_http_attempts,
            inherited.extra_http_scope,
            "extra HTTP",
        )?;
        let (connect_attempts, connect_scope) = resolve_limit(
            self.connect_attempts,
            inherited.connect_attempts,
            inherited.connect_scope,
            "connection",
        )?;
        Ok(EffectiveAttemptLimits {
            extra_http_attempts,
            extra_http_scope,
            connect_attempts,
            connect_scope,
        })
    }
}

/// Validated limits and the configuration scope that supplied each ceiling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectiveAttemptLimits {
    extra_http_attempts: Option<u64>,
    extra_http_scope: Option<AttemptLimitScope>,
    connect_attempts: Option<u64>,
    connect_scope: Option<AttemptLimitScope>,
}

impl EffectiveAttemptLimits {
    /// Effective maximum extra HTTP submissions, or no aggregate ceiling.
    pub const fn extra_http_attempts(self) -> Option<u64> {
        self.extra_http_attempts
    }

    /// Scope supplying the finite ceiling, absent when the limit is unset.
    pub const fn extra_http_scope(self) -> Option<AttemptLimitScope> {
        self.extra_http_scope
    }

    /// Maximum backend connection starts, or no aggregate ceiling.
    pub const fn connect_attempts(self) -> Option<u64> {
        self.connect_attempts
    }

    /// Scope supplying the effective connection ceiling.
    pub const fn connect_scope(self) -> Option<AttemptLimitScope> {
        self.connect_scope
    }
}

/// Completion state of the observed public request operation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The request future has not started executing.
    #[default]
    Pending,
    /// Request execution is in progress; counts may still change.
    Active,
    /// The public request returned a response, including a non-success status.
    Succeeded,
    /// The public request returned an error.
    Failed,
    /// The caller dropped the active request future.
    Cancelled,
}

impl AttemptOutcome {
    /// Stable name used in diagnostic output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the public request operation has finished.
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// Why an attempt or recovery was denied, without replacing its original result.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptDenialReason {
    ExtraHttpLimit,
    ConnectLimit,
    ReplayDenied,
    BodyUnavailable,
    ProtocolOwnerExhausted,
    Cancelled,
    Deadline,
    MissingContext,
    InvalidConfiguration,
    CounterExhausted,
}

impl AttemptDenialReason {
    /// Stable reason code used in diagnostic output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExtraHttpLimit => "extra_http_limit",
            Self::ConnectLimit => "connect_limit",
            Self::ReplayDenied => "replay_denied",
            Self::BodyUnavailable => "body_unavailable",
            Self::ProtocolOwnerExhausted => "protocol_owner_exhausted",
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::MissingContext => "missing_context",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::CounterExhausted => "counter_exhausted",
        }
    }
}

/// Bounded snapshot of one logical request's attempt accounting.
///
/// Counts describe committed backend submissions, not peer receipt. A failed or
/// cancelled submission remains charged. Streaming success ends this accounting
/// at response publication; subsequent body reads do not authorize more HTTP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptSummary {
    pub(crate) started: bool,
    pub(crate) effective_limits: Option<EffectiveAttemptLimits>,
    pub(crate) http_submissions: u64,
    pub(crate) extra_http_submissions: u64,
    pub(crate) redirects: u64,
    pub(crate) recoveries: u64,
    pub(crate) connect_initiations: u64,
    pub(crate) probe_suppressed_by_connect_limit: bool,
    pub(crate) outcome: AttemptOutcome,
    pub(crate) denial_reason: Option<AttemptDenialReason>,
}

impl AttemptSummary {
    /// Whether the public request future began executing.
    pub const fn started(self) -> bool {
        self.started
    }

    /// Resolved limits, absent before resolution or if configuration is invalid.
    pub const fn effective_limits(self) -> Option<EffectiveAttemptLimits> {
        self.effective_limits
    }

    /// All committed initial, redirect and replacement HTTP submissions.
    pub const fn http_submissions(self) -> u64 {
        self.http_submissions
    }

    /// Committed replacement submissions charged against the extra HTTP limit.
    pub const fn extra_http_submissions(self) -> u64 {
        self.extra_http_submissions
    }

    /// Followed redirects that issued a normal HTTP submission entitlement.
    pub const fn redirects(self) -> u64 {
        self.redirects
    }

    /// Approved recovery decisions, including ones cancelled before submission.
    pub const fn recoveries(self) -> u64 {
        self.recoveries
    }

    /// Backend TCP/QUIC starts, including failed starts and race losers.
    pub const fn connect_initiations(self) -> u64 {
        self.connect_initiations
    }

    /// Whether a finite connection cap suppressed an optional detached probe.
    pub const fn probe_suppressed_by_connect_limit(self) -> bool {
        self.probe_suppressed_by_connect_limit
    }

    /// Current completion state; active snapshots may still change.
    pub const fn outcome(self) -> AttemptOutcome {
        self.outcome
    }

    /// Final recovery denial, when one determined the request's outcome.
    pub const fn denial_reason(self) -> Option<AttemptDenialReason> {
        self.denial_reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_limit(limit: Option<u64>) -> EffectiveAttemptLimits {
        let limits = match limit {
            Some(limit) => AttemptLimits::default().with_extra_http_attempts(limit),
            None => AttemptLimits::default(),
        };
        limits.resolve(None, AttemptLimitScope::Client).unwrap()
    }

    #[test]
    fn unset_limits_inherit_across_all_scopes() {
        for requested in [None, Some(0), Some(4), Some(u64::MAX)] {
            let client = client_limit(requested);
            let session = AttemptLimits::default()
                .resolve(Some(&client), AttemptLimitScope::Session)
                .unwrap();
            let request = AttemptLimits::default()
                .resolve(Some(&session), AttemptLimitScope::Request)
                .unwrap();
            assert_eq!(session, client);
            assert_eq!(request, client);
            assert_eq!(request.extra_http_attempts(), requested);
            assert_eq!(
                request.extra_http_scope(),
                requested.map(|_| AttemptLimitScope::Client)
            );
        }
    }

    #[test]
    fn a_child_can_install_or_tighten_but_never_relax_a_finite_parent() {
        for scope in [AttemptLimitScope::Session, AttemptLimitScope::Request] {
            for parent_limit in [None, Some(0), Some(4), Some(u64::MAX)] {
                let parent = client_limit(parent_limit);
                for child_limit in [0, 3, 4, 5, u64::MAX] {
                    let requested = AttemptLimits::default().with_extra_http_attempts(child_limit);
                    let result = requested.resolve(Some(&parent), scope);
                    if parent_limit.is_some_and(|limit| child_limit > limit) {
                        assert!(matches!(result, Err(Error::InvalidConfig(_))));
                    } else {
                        let effective = result.unwrap();
                        assert_eq!(effective.extra_http_attempts(), Some(child_limit));
                        assert_eq!(
                            effective.extra_http_scope(),
                            if parent_limit == Some(child_limit) {
                                Some(AttemptLimitScope::Client)
                            } else {
                                Some(scope)
                            }
                        );
                    }
                    assert_eq!(requested.extra_http_attempts(), Some(child_limit));
                    assert_eq!(parent, client_limit(parent_limit));
                }
            }
        }
    }

    #[test]
    fn equal_request_limit_retains_a_tightening_sessions_scope() {
        let client = client_limit(Some(8));
        let session = AttemptLimits::default()
            .with_extra_http_attempts(3)
            .resolve(Some(&client), AttemptLimitScope::Session)
            .unwrap();
        let request = AttemptLimits::default()
            .with_extra_http_attempts(3)
            .resolve(Some(&session), AttemptLimitScope::Request)
            .unwrap();
        assert_eq!(request, session);
        assert_eq!(request.extra_http_scope(), Some(AttemptLimitScope::Session));
    }

    #[test]
    fn clearing_a_child_restores_inheritance_instead_of_disabling_the_parent() {
        let client = client_limit(Some(8));
        let cleared = AttemptLimits::default()
            .with_extra_http_attempts(0)
            .without_extra_http_limit();
        assert_eq!(cleared.extra_http_attempts(), None);
        assert_eq!(
            cleared
                .resolve(Some(&client), AttemptLimitScope::Session)
                .unwrap(),
            client
        );
        assert_eq!(
            cleared.resolve(None, AttemptLimitScope::Client).unwrap(),
            EffectiveAttemptLimits::default()
        );
    }

    #[test]
    fn invalid_child_can_be_replaced_or_cleared_without_poisoning_parent() {
        let parent = client_limit(Some(2));
        let invalid = AttemptLimits::default().with_extra_http_attempts(3);
        assert!(invalid
            .resolve(Some(&parent), AttemptLimitScope::Request)
            .is_err());
        let repaired = invalid
            .with_extra_http_attempts(1)
            .resolve(Some(&parent), AttemptLimitScope::Request)
            .unwrap();
        assert_eq!(repaired.extra_http_attempts(), Some(1));
        assert_eq!(
            repaired.extra_http_scope(),
            Some(AttemptLimitScope::Request)
        );
        assert_eq!(
            invalid
                .without_extra_http_limit()
                .resolve(Some(&parent), AttemptLimitScope::Request)
                .unwrap(),
            parent
        );
        assert_eq!(parent, client_limit(Some(2)));
    }

    #[test]
    fn default_summary_describes_an_unstarted_operation() {
        let summary = AttemptSummary::default();
        assert!(!summary.started());
        assert_eq!(summary.effective_limits(), None);
        assert_eq!(summary.http_submissions(), 0);
        assert_eq!(summary.extra_http_submissions(), 0);
        assert_eq!(summary.redirects(), 0);
        assert_eq!(summary.recoveries(), 0);
        assert_eq!(summary.connect_initiations(), 0);
        assert!(!summary.probe_suppressed_by_connect_limit());
        assert_eq!(summary.outcome(), AttemptOutcome::Pending);
        assert!(!summary.outcome().is_final());
        assert_eq!(summary.denial_reason(), None);
    }

    #[test]
    fn connection_limits_inherit_tighten_and_clear_independently() {
        for parent in [None, Some(0), Some(4), Some(u64::MAX)] {
            let configured = parent
                .map_or_else(AttemptLimits::default, |n| {
                    AttemptLimits::default().with_connect_attempts(n)
                })
                .with_extra_http_attempts(2);
            let effective = configured.resolve(None, AttemptLimitScope::Client).unwrap();
            for child in [0, 3, 4, 5, u64::MAX] {
                let config = AttemptLimits::default().with_connect_attempts(child);
                let resolved = config.resolve(Some(&effective), AttemptLimitScope::Session);
                if parent.is_some_and(|n| child > n) {
                    assert!(resolved.is_err());
                } else {
                    let resolved = resolved.unwrap();
                    assert_eq!(resolved.connect_attempts(), Some(child));
                    assert_eq!(resolved.extra_http_attempts(), Some(2));
                    assert_eq!(
                        resolved.connect_scope(),
                        Some(if parent == Some(child) {
                            AttemptLimitScope::Client
                        } else {
                            AttemptLimitScope::Session
                        })
                    );
                }
                assert_eq!(
                    config
                        .without_connect_limit()
                        .resolve(Some(&effective), AttemptLimitScope::Request)
                        .unwrap(),
                    effective
                );
            }
            assert_eq!(
                configured.without_extra_http_limit().connect_attempts(),
                parent
            );
        }
    }

    #[test]
    fn diagnostic_codes_and_terminal_outcomes_are_stable() {
        for (scope, code) in [
            (AttemptLimitScope::Client, "client"),
            (AttemptLimitScope::Session, "session"),
            (AttemptLimitScope::Request, "request"),
        ] {
            assert_eq!(scope.as_str(), code);
        }
        for (outcome, code, final_state) in [
            (AttemptOutcome::Pending, "pending", false),
            (AttemptOutcome::Active, "active", false),
            (AttemptOutcome::Succeeded, "succeeded", true),
            (AttemptOutcome::Failed, "failed", true),
            (AttemptOutcome::Cancelled, "cancelled", true),
        ] {
            assert_eq!(outcome.as_str(), code);
            assert_eq!(outcome.is_final(), final_state);
        }
        for (reason, code) in [
            (AttemptDenialReason::ExtraHttpLimit, "extra_http_limit"),
            (AttemptDenialReason::ReplayDenied, "replay_denied"),
            (AttemptDenialReason::BodyUnavailable, "body_unavailable"),
            (
                AttemptDenialReason::ProtocolOwnerExhausted,
                "protocol_owner_exhausted",
            ),
            (AttemptDenialReason::Cancelled, "cancelled"),
            (AttemptDenialReason::Deadline, "deadline"),
            (AttemptDenialReason::MissingContext, "missing_context"),
            (
                AttemptDenialReason::InvalidConfiguration,
                "invalid_configuration",
            ),
            (AttemptDenialReason::CounterExhausted, "counter_exhausted"),
        ] {
            assert_eq!(reason.as_str(), code);
        }
    }
}
