use std::sync::Arc;

use parking_lot::Mutex;

use crate::attempts::{AttemptDenialReason, AttemptOutcome, AttemptSummary};
use crate::session::execution::RequestExecution;

enum Observation {
    Pending,
    Cancelled,
    Bound(RequestExecution),
}

/// Read-only observation of one request, including cancellation and failures.
///
/// Create it with [`RequestBuilder::observe_attempts`](crate::session::RequestBuilder::observe_attempts)
/// before spawning the request. A snapshot is provisional until its outcome is
/// final. After aborting a task, await its termination before expecting final
/// counts. Keeping this observer alive does not keep request authority alive.
#[derive(Clone)]
pub struct AttemptObserver {
    inner: Arc<Mutex<Observation>>,
}

impl AttemptObserver {
    /// Take a bounded snapshot without including URLs, headers, or body data.
    pub fn snapshot(&self) -> AttemptSummary {
        match &*self.inner.lock() {
            Observation::Pending => AttemptSummary::default(),
            Observation::Cancelled => AttemptSummary {
                outcome: AttemptOutcome::Cancelled,
                denial_reason: Some(AttemptDenialReason::Cancelled),
                ..AttemptSummary::default()
            },
            Observation::Bound(execution) => execution.snapshot_summary(),
        }
    }
}

pub(crate) struct ObservationBinding {
    observer: AttemptObserver,
}

impl ObservationBinding {
    pub(crate) fn new() -> Self {
        Self {
            observer: AttemptObserver {
                inner: Arc::new(Mutex::new(Observation::Pending)),
            },
        }
    }

    pub(crate) fn observer(&self) -> AttemptObserver {
        self.observer.clone()
    }

    pub(crate) fn bind(self, execution: &RequestExecution) {
        *self.observer.inner.lock() = Observation::Bound(execution.clone());
    }
}

impl Drop for ObservationBinding {
    fn drop(&mut self) {
        let mut observation = self.observer.inner.lock();
        if matches!(*observation, Observation::Pending) {
            *observation = Observation::Cancelled;
        }
    }
}
