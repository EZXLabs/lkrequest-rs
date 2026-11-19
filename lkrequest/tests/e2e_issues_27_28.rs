//! Loopback regression cases promoted from the issues 27/28 baseline audit.

#[path = "e2e_issues_27_28/hsts.rs"]
mod hsts;
#[path = "e2e_issues_27_28/pool.rs"]
mod pool;
#[path = "e2e_issues_27_28/proxy.rs"]
mod proxy;
#[cfg(feature = "quic-h3")]
#[path = "e2e_issues_27_28/race.rs"]
mod race;
#[path = "e2e_issues_27_28/support.rs"]
mod support;
#[path = "e2e_issues_27_28/websocket.rs"]
mod websocket;
