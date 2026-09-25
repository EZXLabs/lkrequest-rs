//! Per-session pool of outer MASQUE connections.
//!
//! RFC 9298 multiplexes CONNECT-UDP tunnels over one HTTP/3 connection exactly
//! so a client does not pay a handshake per target, so a session visiting ten
//! origins through one proxy opens one outer connection and ten tunnels. That
//! sharing stops at the session boundary: this pool hangs off
//! [`SessionInner`](super::SessionInner), the same place the TCP/H2 pool and
//! the cookie jar live, so two sessions never meet on the same outer connection
//! even when they are configured with the same proxy. A `Session` is a virtual
//! browser user; letting two of them share a proxy connection would let the
//! proxy correlate identities the client went out of its way to separate.
//!
//! The pool is also where the tunnel lifecycle policy from
//! `design/masque-connect-udp-design.md` is applied — see [`MasquePool::sweep`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use crate::error::Result;
use crate::proxy::masque::{MasqueConnection, MasqueOuterConfig};
use crate::proxy::ProxyConfig;

/// One proxy identity's outer connection.
///
/// The connection sits behind an async mutex rather than the pool's own lock
/// because establishing it is a QUIC handshake: two requests that arrive
/// together must end up on *one* connection, which means the second has to wait
/// for the first's handshake rather than start its own. Keeping that wait per
/// proxy means a slow proxy cannot stall connections to a different one.
#[derive(Default)]
struct SlotState {
    connection: Option<MasqueConnection>,
    /// When this slot last handed a connection out. Only consulted once the
    /// connection carries no tunnels at all.
    last_used: Option<Instant>,
}

#[derive(Default)]
struct Slot {
    state: tokio::sync::Mutex<SlotState>,
}

/// Outer MASQUE connections held by one session, keyed by
/// [`ProxyConfig::identity`].
///
/// The key is the proxy's identity rather than its address because credentials
/// are part of what a tunnel is opened with: two `masque://` URLs pointing at
/// the same host with different credentials are different proxies, and sharing
/// a connection between them would send one's tunnels under the other's
/// `proxy-authorization`.
#[derive(Default)]
pub(crate) struct MasquePool {
    slots: Mutex<HashMap<String, Arc<Slot>>>,
}

impl std::fmt::Debug for MasquePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasquePool")
            .field("proxies", &self.slots.lock().len())
            .finish()
    }
}

impl MasquePool {
    /// Reuse this session's outer connection to `proxy`, or establish one.
    ///
    /// `proxy_addr` is already resolved: the bridge takes a `SocketAddr` on
    /// purpose so that DNS stays with the session's resolver instead of
    /// becoming a second, differently-configured policy inside the proxy layer.
    pub(crate) async fn acquire(
        &self,
        proxy: &ProxyConfig,
        proxy_addr: SocketAddr,
        config: &MasqueOuterConfig,
    ) -> Result<MasqueConnection> {
        let slot = {
            let mut slots = self.slots.lock();
            slots.entry(proxy.identity()).or_default().clone()
        };

        let connection = {
            let mut state = slot.state.lock().await;
            // A connection the proxy has since closed is worse than none: every
            // tunnel opened on it would fail. Replace it rather than hand it out.
            let reusable = state
                .connection
                .as_ref()
                .filter(|connection| connection.is_live())
                .cloned();
            let connection = match reusable {
                Some(connection) => connection,
                None => {
                    let connection = MasqueConnection::connect(proxy, proxy_addr, config).await?;
                    state.connection = Some(connection.clone());
                    connection
                }
            };
            state.last_used = Some(Instant::now());
            connection
        };

        self.sweep(config);
        Ok(connection)
    }

    /// Apply the lifecycle policy to every cached connection.
    ///
    /// Run on acquisition rather than from a timer: a session that is not making
    /// requests is not accumulating tunnels either, and a background task would
    /// have to be owned, cancelled and kept from outliving the session for no
    /// gain. The cost is that the last tunnels of an idle session are retired
    /// when the session is next used, or when it is dropped — whichever comes
    /// first.
    ///
    /// The one rule worth spelling out: **an outer connection that still has
    /// live tunnels is never retired**. With
    /// [`MasqueOuterConfig::tunnel_idle_timeout`] set to `None` nothing retires
    /// those tunnels, so retiring the connection beneath them would turn "never
    /// reclaim" into "reclaim as soon as the outer connection goes idle" — the
    /// failure mode `design/masque-connect-udp-design.md` calls out by name.
    fn sweep(&self, config: &MasqueOuterConfig) {
        let now = Instant::now();
        let snapshot: Vec<(String, Arc<Slot>)> = {
            let slots = self.slots.lock();
            slots
                .iter()
                .map(|(identity, slot)| (identity.clone(), slot.clone()))
                .collect()
        };

        let mut retired = Vec::new();
        for (identity, slot) in snapshot {
            // A slot another task is using is a slot that is by definition not
            // idle; skipping it keeps the sweep off the request path's critical
            // section entirely.
            let Ok(mut state) = slot.state.try_lock() else {
                continue;
            };
            let Some(connection) = state.connection.as_ref() else {
                retired.push(identity);
                continue;
            };

            if !connection.is_live() {
                state.connection = None;
                retired.push(identity);
                continue;
            }

            connection.reap_tunnels(config.tunnel_idle_timeout, config.max_idle_tunnels);

            if connection.tunnel_count() > 0 {
                continue;
            }
            let Some(timeout) = config.tunnel_idle_timeout else {
                continue;
            };
            let idle = state
                .last_used
                .map(|last| now.saturating_duration_since(last))
                .unwrap_or_default();
            if idle >= timeout {
                state.connection = None;
                retired.push(identity);
            }
        }

        if retired.is_empty() {
            return;
        }
        let mut slots = self.slots.lock();
        for identity in retired {
            // Re-check under the pool lock: another task may have refilled the
            // slot between the two locks, and dropping a live connection here
            // would strand the tunnels it is carrying.
            let refilled = slots
                .get(&identity)
                .is_some_and(|slot| match slot.state.try_lock() {
                    Ok(state) => state.connection.is_some(),
                    Err(_) => true,
                });
            if !refilled {
                slots.remove(&identity);
            }
        }
    }
}
