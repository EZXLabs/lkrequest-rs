//! Coordinate reusable TCP connections until protocol readiness, not just ALPN.

pub(crate) use super::acquisition::ConnectJob as TcpHandshakeGuard;
use super::{PreferredHttpVersion, Session};
use crate::connection_pool::{AcquiredConnection, ConnectionKey, Scheme};
use crate::error::Result;

pub(crate) enum TcpAcquisition<'a> {
    Ready(lkh2::H2ReadySender),
    Connect(Option<TcpHandshakeGuard<'a>>),
}

impl Session {
    pub(crate) async fn acquire_tcp<'a>(
        &'a self,
        key: &'a ConnectionKey,
        preference: PreferredHttpVersion,
    ) -> Result<TcpAcquisition<'a>> {
        if preference == PreferredHttpVersion::Http1Only
            || (key.scheme == Scheme::Http && preference != PreferredHttpVersion::Http2Only)
        {
            return Ok(TcpAcquisition::Connect(None));
        }
        loop {
            let leadership = self.inner.acquisition.tcp.try_start(key);
            let guard = match leadership {
                Ok(guard) => guard,
                Err(mut receiver) => {
                    let _ = receiver.changed().await;
                    if *receiver.borrow() && preference != PreferredHttpVersion::Http2Only {
                        return Ok(TcpAcquisition::Connect(None));
                    }
                    continue;
                }
            };
            // Recheck after election: a prior leader may have pooled H2 between
            // the caller's initial pool lookup and our coordination lookup.
            let pooled = self.inner.pool.lock().try_acquire_h2_pooled_internal(key);
            if let Some(AcquiredConnection::H2 { sender, token }) = pooled {
                match sender.ready().await {
                    Ok(sender) => return Ok(TcpAcquisition::Ready(sender)),
                    Err(_) => {
                        self.inner.pool.lock().remove_acquired(key, &token);
                    }
                }
            }
            return Ok(TcpAcquisition::Connect(Some(guard)));
        }
    }
}
