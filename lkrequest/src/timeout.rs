use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{Error, Result};

pub(crate) fn display_duration(duration: Option<Duration>) -> String {
    match duration {
        Some(duration) => format!("{duration:?}"),
        None => "disabled".into(),
    }
}

pub(crate) async fn optional<T>(
    duration: Option<Duration>,
    future: impl Future<Output = T>,
) -> std::result::Result<T, tokio::time::error::Elapsed> {
    match duration {
        Some(duration) => tokio::time::timeout(duration, future).await,
        None => Ok(future.await),
    }
}

/// One deadline shared by a public request call and its streaming response.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RequestTimeout {
    deadline: Option<Instant>,
    duration: Option<Duration>,
}

impl RequestTimeout {
    pub(crate) fn new(duration: Option<Duration>) -> Self {
        Self {
            deadline: duration.and_then(|value| Instant::now().checked_add(value)),
            duration,
        }
    }

    pub(crate) fn deadline(self) -> Option<Instant> {
        self.deadline
    }

    pub(crate) fn error(self) -> Error {
        Error::timeout(
            format!(
                "request timed out (total deadline of {:?} exceeded)",
                self.duration.unwrap()
            ),
            None,
            self.duration,
        )
    }

    pub(crate) fn check(self) -> Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(self.error());
        }
        Ok(())
    }

    pub(crate) async fn run<T>(self, future: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        let result = match self.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| self.error())?,
            None => future.await,
        };
        self.check()?;
        result
    }
}
