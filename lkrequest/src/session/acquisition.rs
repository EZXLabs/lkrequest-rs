//! Session-local ownership of in-flight connection establishment.

use std::collections::HashMap;

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::connection_pool::ConnectionKey;

#[derive(Default)]
pub(crate) struct AcquisitionCoordinator {
    pub tcp: ConnectJobs,
    #[cfg(feature = "quic-h3")]
    pub quic: ConnectJobs,
}

#[derive(Default)]
pub(crate) struct ConnectJobs {
    pending: Mutex<HashMap<ConnectionKey, watch::Receiver<bool>>>,
}

impl ConnectJobs {
    pub fn try_start<'a>(
        &'a self,
        key: &'a ConnectionKey,
    ) -> Result<ConnectJob<'a>, watch::Receiver<bool>> {
        let mut pending = self.pending.lock();
        if let Some(receiver) = pending.get(key) {
            return Err(receiver.clone());
        }
        let (completion, receiver) = watch::channel(false);
        pending.insert(key.clone(), receiver);
        Ok(ConnectJob {
            jobs: self,
            key,
            completion,
        })
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.pending.lock().len()
    }
}

pub(crate) struct ConnectJob<'a> {
    jobs: &'a ConnectJobs,
    key: &'a ConnectionKey,
    completion: watch::Sender<bool>,
}

impl ConnectJob<'_> {
    pub fn release_h1(self) {
        self.completion.send_replace(true);
    }
}

impl Drop for ConnectJob<'_> {
    fn drop(&mut self) {
        // Remove before closing the channel: even an unpolled waiter can then
        // observe completion and elect a replacement after failure/cancellation.
        self.jobs.pending.lock().remove(self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::pipeline;

    fn key() -> ConnectionKey {
        pipeline::parse_request_target("https://localhost/", None)
            .unwrap()
            .conn_key
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_cancel_the_leader() {
        let jobs = ConnectJobs::default();
        let key = key();
        let leader = jobs.try_start(&key).ok().unwrap();
        let waiter = jobs.try_start(&key).err().unwrap();
        drop(waiter);
        assert!(jobs.try_start(&key).is_err());
        assert_eq!(jobs.len(), 1);
        drop(leader);
        assert!(jobs.try_start(&key).is_ok());
    }

    #[tokio::test]
    async fn cancelled_leader_wakes_unpolled_waiters_without_removing_replacement() {
        let jobs = ConnectJobs::default();
        let key = key();
        let leader = jobs.try_start(&key).ok().unwrap();
        let mut waiter = jobs.try_start(&key).err().unwrap();
        drop(leader);
        let replacement = jobs.try_start(&key).ok().unwrap();
        assert!(waiter.changed().await.is_err());
        assert!(jobs.try_start(&key).is_err());
        drop(replacement);
        assert_eq!(jobs.len(), 0);
    }

    #[tokio::test]
    async fn h1_release_is_observable_before_a_waiter_polls() {
        let jobs = ConnectJobs::default();
        let key = key();
        let leader = jobs.try_start(&key).ok().unwrap();
        let mut waiter = jobs.try_start(&key).err().unwrap();
        leader.release_h1();
        let _ = waiter.changed().await;
        assert!(*waiter.borrow());
        assert_eq!(jobs.len(), 0);
    }

    #[test]
    fn sessions_and_protocols_do_not_share_jobs() {
        let first = AcquisitionCoordinator::default();
        let second = AcquisitionCoordinator::default();
        let key = key();
        let _first = first.tcp.try_start(&key).ok().unwrap();
        let _second = second.tcp.try_start(&key).ok().unwrap();
        assert_eq!(first.tcp.len(), 1);
        assert_eq!(second.tcp.len(), 1);
        #[cfg(feature = "quic-h3")]
        {
            let _quic = first.quic.try_start(&key).ok().unwrap();
            assert_eq!(first.quic.len(), 1);
            assert_eq!(second.quic.len(), 0);
        }
    }
}
