//! Proxy configuration, connection, and rotation.
//!
//! Supports:
//! - HTTP CONNECT proxies (`http://host:port`, `https://host:port`)
//! - SOCKS5 proxies (`socks5://host:port`)
//! - MASQUE proxies (`masque://host:port`, RFC 9298 CONNECT-UDP — UDP/QUIC
//!   only), with the `masque` feature; without it `masque://` is rejected by
//!   [`ProxyConfig::parse`]
//! - Optional authentication (`user:pass@host:port`, or
//!   [`ProxyCredential`] for `Preshared`/`Bearer`-style credentials)
//! - Proxy rotation strategies for [`SessionPool`](crate::session_pool::SessionPool)

mod config;
mod connect;
/// MASQUE CONNECT-UDP I/O bridge. Requires the `masque` feature, which implies
/// `quic-h3`: the tunnel only exists as an outer HTTP/3 connection, and the
/// thing it carries is an inner QUIC one.
#[cfg(feature = "masque")]
pub mod masque;
mod probe;
mod provider;
pub(crate) mod socks5_udp;

pub use config::{
    ProxyAuth, ProxyAuthHeader, ProxyAuthenticator, ProxyConfig, ProxyCredential, ProxyScheme,
};
#[cfg(feature = "masque")]
pub use masque::{MasqueConnection, MasqueOuterConfig, MasqueUdpSocket};
pub use probe::{
    Socks5UdpProbeConfig, Socks5UdpProbeMode, Socks5UdpProbePhase, Socks5UdpProbeReport,
    Socks5UdpProbeSupport, Socks5UdpProbeTarget,
};
pub use provider::{
    BufferedProxyProvider, FnProxyProvider, ProxyProvider, ProxyRotator, RotationStrategy,
};
