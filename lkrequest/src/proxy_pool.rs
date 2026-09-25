//! ProxyPool — manages proxy allocation with concurrency control and health tracking.
//!
//! `ProxyPool` decouples proxy management from session management, providing
//! a standalone pool of proxies that can be acquired and released independently.
//!
//! ## Features
//!
//! - **Pluggable proxy provider**: same [`ProxyProvider`]
//!   ecosystem as [`SessionPool`](crate::session_pool::SessionPool).
//! - **Concurrency control**: semaphore-based limit on concurrent proxy usage.
//! - **Sliding window failure counting**: `mark_bad()` tracks failures per proxy.
//! - **Automatic cooldown recovery**: background task cleans up expired cooldowns.
//! - **Permanent removal**: proxies that enter cooldown too many times are removed.
//! - **Health checking**: optional active TCP probes for static proxy lists.
//!   MASQUE proxies are skipped unless `HealthCheckConfig::tunnel_probe` asks
//!   for a real CONNECT-UDP probe *and* `masque_outer_config` says how to build
//!   its outer connection (both require the `masque` feature).
//!
//! ## Use Cases
//!
//! Use `ProxyPool` when you need proxy lifecycle management without session reuse —
//! for example, captcha solving where each task requires a fresh
//! [`Session`](crate::session::Session) but shares a managed proxy pool.
//!
//! For traditional scraping where session reuse (cookies, connections) is desired,
//! use [`SessionPool`](crate::session_pool::SessionPool) which builds on `ProxyPool`
//! internally.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use crate::proxy::{
    BufferedProxyProvider, FnProxyProvider, ProxyConfig, ProxyProvider, ProxyRotator,
    RotationStrategy,
};

// ---------------------------------------------------------------------------
// ProxyPool
// ---------------------------------------------------------------------------

/// A pool of proxies with concurrency control and health management.
///
/// `ProxyPool` provides a standalone proxy management layer that can be used
/// independently of [`SessionPool`](crate::session_pool::SessionPool).  Each
/// call to [`acquire()`](ProxyPool::acquire) returns a [`ProxyGuard`] holding
/// a proxy configuration and a semaphore permit.  When the guard is dropped,
/// the permit is released, allowing another caller to proceed.
///
/// # Example — Standalone use (captcha solver)
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use std::sync::Arc;
/// use lkrequest::proxy_pool::ProxyPool;
///
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// let counter = Arc::new(AtomicU64::new(0));
/// let pool = ProxyPool::builder()
///     .proxy_fn(move || {
///         let id = counter.fetch_add(1, Ordering::Relaxed);
///         format!("http://user-sid-{id:06}:pass@gateway.com:7777")
///     })
///     .max_proxies(50)
///     .build();
///
/// let guard = pool.acquire().await;
/// let session = client.session()
///     .proxy_config(guard.proxy().unwrap().clone())
///     .build();
/// let resp = session.get("https://example.com/captcha/solve").send().await?;
/// // guard dropped → permit released
/// # Ok(())
/// # }
/// ```
pub struct ProxyPool {
    pub(crate) inner: Arc<ProxyPoolInner>,
}

pub(crate) struct ProxyPoolInner {
    pub(crate) proxy_provider: Box<dyn ProxyProvider>,
    semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    max_proxies: usize,
    cooldown: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    permanently_removed: Mutex<HashSet<String>>,
    cooldown_counts: Mutex<HashMap<String, u32>>,
    pub(crate) bad_proxy_config: BadProxyConfig,
    health_check: Option<HealthCheckConfig>,
    pub(crate) shutdown: AtomicBool,
}

impl ProxyPool {
    /// Start building a new `ProxyPool`.
    pub fn builder() -> ProxyPoolBuilder {
        ProxyPoolBuilder::new()
    }

    /// Acquire a proxy from the pool.
    ///
    /// Waits for a semaphore permit if the pool is at capacity, then selects
    /// the next usable proxy from the provider (skipping proxies in cooldown
    /// or permanently removed).
    ///
    /// Returns a [`ProxyGuard`] that releases the permit on drop.
    pub async fn acquire(&self) -> ProxyGuard {
        tracing::trace!("proxy_pool.acquiring");

        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        let proxy = self.next_usable_proxy().await;

        tracing::debug!("proxy_pool.acquired");

        ProxyGuard {
            proxy,
            pool: Arc::clone(&self.inner),
            _permit: permit,
        }
    }

    /// Mark a proxy as bad and acquire a fresh one.
    ///
    /// Note: `bad_guard` still holds its permit. If the pool is at capacity,
    /// this will block until another permit is released elsewhere.
    pub async fn acquire_fresh(&self, bad_guard: &ProxyGuard) -> ProxyGuard {
        bad_guard.mark_bad();
        self.acquire().await
    }

    /// Returns the maximum number of concurrent proxy permits.
    pub fn max_concurrent(&self) -> usize {
        self.inner.max_proxies
    }

    /// Mark a proxy as bad by its identity string.
    ///
    /// Feeds the sliding-window failure counter.  When the threshold is reached,
    /// the proxy enters cooldown.  After too many cooldowns, permanent removal.
    ///
    /// No-op for dynamic providers (ephemeral identities).
    pub fn mark_bad_proxy(&self, identity: &str) {
        record_bad_proxy(&self.inner, identity.to_string());
    }

    /// Select the next usable proxy, skipping those in cooldown or removed.
    pub(crate) async fn next_usable_proxy(&self) -> Option<ProxyConfig> {
        let provider = &self.inner.proxy_provider;

        if provider.is_dynamic() {
            return provider.next_proxy();
        }

        let proxy_count = provider.len();
        for _ in 0..proxy_count.max(1) {
            if let Some(proxy) = provider.next_proxy() {
                let identity = proxy.identity();

                {
                    let removed = self.inner.permanently_removed.lock().await;
                    if removed.contains(&identity) {
                        tracing::trace!(
                            proxy = %identity,
                            "proxy_pool.skipping_removed_proxy"
                        );
                        continue;
                    }
                }

                let in_cooldown = {
                    let map = self.inner.cooldown.lock().await;
                    map.get(&identity)
                        .is_some_and(|expires| Instant::now() < *expires)
                };

                if !in_cooldown {
                    return Some(proxy);
                }
                tracing::debug!(
                    proxy = %identity,
                    "proxy_pool.skipping_cooldown_proxy",
                );
            } else {
                break;
            }
        }
        None
    }

    fn spawn_maintenance_task(inner: Arc<ProxyPoolInner>) {
        let check_interval = Duration::from_secs(30);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            let mut health_check_due = Instant::now();
            loop {
                interval.tick().await;

                if inner.shutdown.load(Ordering::Relaxed) {
                    tracing::debug!("proxy_pool.maintenance_task_shutdown");
                    break;
                }

                // 1. Clean up expired cooldown entries
                {
                    let mut cooldown = inner.cooldown.lock().await;
                    let now = Instant::now();
                    let before = cooldown.len();
                    cooldown.retain(|_, expires| now < *expires);
                    let recovered = before - cooldown.len();
                    if recovered > 0 {
                        tracing::info!(
                            recovered = recovered,
                            "proxy_pool.cooldown_proxies_recovered",
                        );
                    }
                }

                // 2. Active health checking (static providers only)
                if !inner.proxy_provider.is_dynamic() {
                    if let Some(ref hc_config) = inner.health_check {
                        let now = Instant::now();
                        if now >= health_check_due {
                            health_check_due = now + hc_config.interval;
                            run_health_checks(&inner, hc_config).await;
                        }
                    }
                }
            }
        });
    }
}

impl Clone for ProxyPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) <= 2 {
            self.inner.shutdown.store(true, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyGuard — RAII permit holder
// ---------------------------------------------------------------------------

/// A guard that holds a proxy configuration and its pool permit.
///
/// When dropped, the semaphore permit is released, allowing another
/// [`ProxyPool::acquire`] call to proceed.
pub struct ProxyGuard {
    proxy: Option<ProxyConfig>,
    pool: Arc<ProxyPoolInner>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl ProxyGuard {
    /// Get the proxy configuration held by this guard.
    ///
    /// Returns `None` if no proxy was available from the provider (direct
    /// connection scenario).
    pub fn proxy(&self) -> Option<&ProxyConfig> {
        self.proxy.as_ref()
    }

    /// Mark this guard's proxy as bad.
    ///
    /// Feeds the sliding-window failure counter.  No-op if the proxy is `None`
    /// or the provider is dynamic.
    pub fn mark_bad(&self) {
        if let Some(proxy) = &self.proxy {
            record_bad_proxy(&self.pool, proxy.identity());
        }
    }
}

// ---------------------------------------------------------------------------
// Bad-proxy recording (shared by ProxyPool::mark_bad_proxy and ProxyGuard)
// ---------------------------------------------------------------------------

fn record_bad_proxy(inner: &Arc<ProxyPoolInner>, identity: String) {
    if inner.proxy_provider.is_dynamic() {
        return;
    }

    let pool_inner = Arc::clone(inner);
    tokio::spawn(async move {
        {
            let removed = pool_inner.permanently_removed.lock().await;
            if removed.contains(&identity) {
                return;
            }
        }

        let config = &pool_inner.bad_proxy_config;
        let now = Instant::now();
        let window_start = now - config.window;

        let failure_count = {
            let mut failures = pool_inner.failures.lock().await;
            let entries = failures.entry(identity.clone()).or_default();
            entries.retain(|t| *t > window_start);
            entries.push_back(now);
            entries.len() as u32
        };

        if failure_count >= config.failure_threshold {
            {
                let mut failures = pool_inner.failures.lock().await;
                if let Some(entries) = failures.get_mut(&identity) {
                    entries.clear();
                }
            }

            let mut cooldown_map = pool_inner.cooldown.lock().await;
            let expires = now + config.cooldown_duration;
            cooldown_map.insert(identity.clone(), expires);

            let cumulative = {
                let mut counts = pool_inner.cooldown_counts.lock().await;
                let count = counts.entry(identity.clone()).or_insert(0);
                *count += 1;
                *count
            };

            if cumulative >= config.max_cooldowns {
                let mut removed = pool_inner.permanently_removed.lock().await;
                removed.insert(identity.clone());
                tracing::error!(
                    proxy = %identity,
                    total_cooldowns = cumulative,
                    "proxy_pool.proxy_permanently_removed",
                );
            } else {
                tracing::warn!(
                    proxy = %identity,
                    cooldown_secs = config.cooldown_duration.as_secs(),
                    failures_in_window = failure_count,
                    total_cooldowns = cumulative,
                    "proxy_pool.proxy_entered_cooldown",
                );
            }
        } else {
            tracing::debug!(
                proxy = %identity,
                failures_in_window = failure_count,
                threshold = config.failure_threshold,
                "proxy_pool.proxy_failure_recorded",
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

async fn run_health_checks(inner: &Arc<ProxyPoolInner>, config: &HealthCheckConfig) {
    let removed = inner.permanently_removed.lock().await;
    let proxies: Vec<_> = inner
        .proxy_provider
        .all_proxies()
        .into_iter()
        .filter(|p| !removed.contains(&p.identity()))
        .collect();
    drop(removed);

    if proxies.is_empty() {
        return;
    }

    tracing::debug!(
        proxy_count = proxies.len(),
        target = %format_args!("{}:{}", config.target_host, config.target_port),
        "proxy_pool.health_check_starting",
    );

    let resolver = crate::dns::SystemDns;
    for proxy in &proxies {
        let identity = proxy.identity();

        // MASQUE proxies never take the TCP path: a reachable port says nothing
        // about whether CONNECT-UDP works, so judging them by `proxy.connect()`
        // would be a false positive.  See `masque_health_check`.
        if proxy.scheme.is_masque() {
            masque_health_check(inner, proxy, &identity, config, &resolver).await;
            continue;
        }

        let result = tokio::time::timeout(
            config.timeout,
            proxy.connect(&config.target_host, config.target_port, None, &resolver),
        )
        .await;

        match result {
            Ok(Ok(_stream)) => record_health_check_success(inner, &identity).await,
            Ok(Err(e)) => {
                tracing::debug!(
                    proxy = %identity,
                    error = %e,
                    "proxy_pool.health_check_failed",
                );
                record_health_check_failure(inner, identity).await;
            }
            Err(_timeout) => {
                tracing::debug!(proxy = %identity, "proxy_pool.health_check_timeout");
                record_health_check_failure(inner, identity).await;
            }
        }
    }
}

/// A proxy answered the probe: drop it out of cooldown if it was in one.
async fn record_health_check_success(inner: &Arc<ProxyPoolInner>, identity: &str) {
    let was_in_cooldown = {
        let mut cooldown = inner.cooldown.lock().await;
        cooldown.remove(identity).is_some()
    };
    if was_in_cooldown {
        tracing::info!(
            proxy = %identity,
            "proxy_pool.health_check_recovered_proxy",
        );
    } else {
        tracing::trace!(proxy = %identity, "proxy_pool.health_check_ok");
    }
}

/// A probe failed or timed out: feed the sliding-window failure counter.
async fn record_health_check_failure(inner: &Arc<ProxyPoolInner>, identity: String) {
    let bp = &inner.bad_proxy_config;
    let now = Instant::now();
    let window_start = now - bp.window;
    let mut failures = inner.failures.lock().await;
    let entries = failures.entry(identity).or_default();
    entries.retain(|t| *t > window_start);
    entries.push_back(now);
}

/// Health-check one MASQUE proxy.
///
/// With [`HealthCheckConfig::tunnel_probe`] off (the default) this is a no-op:
/// the proxy is neither credited nor blamed, keeps whatever cooldown it has and
/// is never blacklisted by the active checker.  With it on *and* an outer
/// config supplied, a real CONNECT-UDP handshake decides.
///
/// The flag on with no
/// [`masque_outer_config`](HealthCheckConfig::masque_outer_config) is the third
/// case, and it skips too: probing against whatever trust anchors happened to
/// be lying around would fail every privately-fronted proxy and feed the
/// blacklist with false negatives.  Saying nothing is always recoverable;
/// blacklisting a healthy proxy is not.
#[cfg(feature = "masque")]
async fn masque_health_check(
    inner: &Arc<ProxyPoolInner>,
    proxy: &ProxyConfig,
    identity: &str,
    config: &HealthCheckConfig,
    resolver: &crate::dns::SystemDns,
) {
    if !config.tunnel_probe {
        tracing::trace!(proxy = %identity, "proxy_pool.health_check_skipped_masque");
        return;
    }

    let Some(outer) = config.masque_outer_config.as_ref() else {
        tracing::warn!(
            proxy = %identity,
            reason = "`HealthCheckConfig::tunnel_probe` is on but `masque_outer_config` is \
                      unset, so the probe has no trust anchors to verify this proxy against. \
                      Probing with a guessed default would fail every proxy fronted by a \
                      private CA and blacklist it. Set `masque_outer_config` (e.g. from \
                      `Client::masque_config()`) to enable the probe.",
            "proxy_pool.health_check_skipped_masque_no_outer_config",
        );
        return;
    };

    match tokio::time::timeout(
        config.timeout,
        masque_tunnel_probe(proxy, config, outer, resolver),
    )
    .await
    {
        Ok(Ok(())) => record_health_check_success(inner, identity).await,
        Ok(Err(e)) => {
            tracing::debug!(
                proxy = %identity,
                error = %e,
                "proxy_pool.health_check_failed",
            );
            record_health_check_failure(inner, identity.to_string()).await;
        }
        Err(_timeout) => {
            tracing::debug!(proxy = %identity, "proxy_pool.health_check_timeout");
            record_health_check_failure(inner, identity.to_string()).await;
        }
    }
}

/// Without the `masque` feature there is no CONNECT-UDP client to probe with,
/// so a MASQUE proxy is always skipped — the same conclusion `tunnel_probe =
/// false` reaches.  A missing feature must not abort the round: health checking
/// is a background loop, and every other proxy in the list still needs checking.
#[cfg(not(feature = "masque"))]
async fn masque_health_check(
    _inner: &Arc<ProxyPoolInner>,
    _proxy: &ProxyConfig,
    identity: &str,
    _config: &HealthCheckConfig,
    _resolver: &crate::dns::SystemDns,
) {
    tracing::trace!(proxy = %identity, "proxy_pool.health_check_skipped_masque");
}

/// One CONNECT-UDP handshake against `proxy`, torn down immediately.
///
/// Establishes the outer HTTP/3 connection, opens a tunnel to the configured
/// health-check target — which is where the proxy's response is validated
/// ([`MasqueConnection::open_tunnel`](crate::proxy::masque::MasqueConnection::open_tunnel))
/// — then closes both.  Nothing is sent through the tunnel: reaching `Ready`
/// is the liveness signal.
///
/// The proxy host is resolved here because
/// [`MasqueConnection::connect`](crate::proxy::masque::MasqueConnection::connect)
/// takes an already-resolved address.
///
/// The outer connection is built from `outer`, which the caller supplied
/// through [`HealthCheckConfig::masque_outer_config`] — never from a default,
/// so the probe verifies the proxy against exactly the trust anchors the real
/// requests would use.
#[cfg(feature = "masque")]
async fn masque_tunnel_probe(
    proxy: &ProxyConfig,
    config: &HealthCheckConfig,
    outer: &crate::proxy::MasqueOuterConfig,
    resolver: &crate::dns::SystemDns,
) -> crate::error::Result<()> {
    use crate::dns::DnsResolver;
    use crate::error::{Error, ProxyErrorKind};
    use crate::proxy::masque::MasqueConnection;

    let (proxy_host, proxy_port) = proxy.host_port();
    let addresses = resolver
        .resolve(proxy_host, proxy_port)
        .await
        .map_err(|error| {
            Error::proxy(
                ProxyErrorKind::IoError,
                format!("MASQUE health check could not resolve {proxy_host}: {error}"),
                Some(Box::new(error)),
            )
        })?;
    let proxy_addr = addresses.into_iter().next().ok_or_else(|| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("MASQUE health check: {proxy_host} resolved to no addresses"),
            None,
        )
    })?;

    let connection = MasqueConnection::connect(proxy, proxy_addr, outer).await?;
    let tunnel = connection
        .open_tunnel(&config.target_host, config.target_port)
        .await?;
    tunnel.close();
    Ok(())
}

// ---------------------------------------------------------------------------
// BadProxyConfig
// ---------------------------------------------------------------------------

/// Configuration for automatic bad-proxy detection and cooldown.
#[derive(Debug, Clone)]
pub struct BadProxyConfig {
    /// Number of failures within `window` to trigger cooldown.
    pub failure_threshold: u32,
    /// Time window for counting failures.
    pub window: Duration,
    /// How long a bad proxy stays in cooldown before being retried.
    pub cooldown_duration: Duration,
    /// Number of times a proxy can enter cooldown before permanent removal.
    /// Set to `u32::MAX` to disable permanent removal.
    pub max_cooldowns: u32,
}

impl Default for BadProxyConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            window: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(300),
            max_cooldowns: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// HealthCheckConfig
// ---------------------------------------------------------------------------

/// Configuration for active proxy health checking.
///
/// When enabled, the pool periodically tests each proxy's connectivity
/// by attempting a TCP connection to a configurable target.  Unhealthy proxies
/// are fed into the bad-proxy detection pipeline, while healthy proxies in
/// cooldown are recovered early.
///
/// Health checks only apply to **static** providers (fixed proxy lists).
/// Dynamic providers (closures) skip health checks since their identities
/// are ephemeral.
///
/// MASQUE proxies are the exception to the TCP probe — see the `tunnel_probe`
/// and `masque_outer_config` fields, which exist only with the `masque`
/// feature.
///
/// # Construction
///
/// `#[non_exhaustive]`: build one from [`Default`] and assign the fields you
/// care about, rather than with a struct literal. The MASQUE fields only exist
/// with the `masque` feature, so a literal would otherwise name a different set
/// of fields depending on which features the final binary happens to turn on —
/// and a downstream crate cannot control that.
///
/// ```rust
/// use lkrequest::proxy_pool::HealthCheckConfig;
/// use std::time::Duration;
///
/// let mut health = HealthCheckConfig::default();
/// health.interval = Duration::from_secs(30);
/// health.target_host = "www.example.com".into();
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HealthCheckConfig {
    /// How often to run health checks (default: 60s).
    pub interval: Duration,
    /// Timeout for a single health check probe (default: 5s).
    ///
    /// Also bounds a MASQUE `tunnel_probe` end to end: DNS, outer QUIC/HTTP-3
    /// handshake and the CONNECT-UDP exchange together.
    pub timeout: Duration,
    /// Target host for health check TCP connection.
    ///
    /// With a MASQUE `tunnel_probe` on, this is also the target a MASQUE proxy
    /// is asked to open a CONNECT-UDP tunnel to.
    pub target_host: String,
    /// Target port for health check (typically 443 or 80).
    pub target_port: u16,
    /// Actively probe `masque://` proxies with a real CONNECT-UDP handshake
    /// (default: `false`).
    ///
    /// The ordinary health check establishes a TCP connection through the proxy
    /// and calls that alive.  For a MASQUE proxy that conclusion is **false**:
    /// CONNECT-UDP (RFC 9298) rides on an outer HTTP/3 connection, so a
    /// reachable TCP port proves nothing about whether the proxy supports HTTP
    /// Datagrams, accepts `connect-udp`, or likes the credentials.
    ///
    /// Therefore:
    ///
    /// - **`false` (default)** — MASQUE proxies are skipped by the active
    ///   checker entirely.  They are neither marked healthy (a skipped proxy
    ///   stays in cooldown until it expires normally) nor marked failing, and
    ///   are never blacklisted by health checking.  Bad MASQUE proxies are
    ///   caught the passive way instead, through
    ///   [`ProxyPool::mark_bad_proxy`] on real request failures.
    /// - **`true`** — each MASQUE proxy gets a genuine probe: connect the outer
    ///   HTTP/3 connection, open a CONNECT-UDP tunnel to
    ///   `target_host:target_port`, verify it becomes ready after a valid 2xx
    ///   response, then close it immediately. Success recovers
    ///   the proxy from cooldown; failure or timeout feeds the bad-proxy
    ///   counter like any other failed check.
    ///
    /// The probe costs a full QUIC handshake per proxy per round, which is one
    /// reason this is opt-in. The other is that it needs to be told how to
    /// build that outer connection: turning this on **without** also setting
    /// [`masque_outer_config`](Self::masque_outer_config) leaves MASQUE proxies
    /// skipped, with a warning. See that field for why.
    ///
    /// Turning this on requires the `masque` feature; without it there is no
    /// CONNECT-UDP client at all, so the field does not exist and MASQUE
    /// proxies are skipped unconditionally (and never blamed for it).
    ///
    /// Non-MASQUE proxies are unaffected by this setting.
    #[cfg(feature = "masque")]
    pub tunnel_probe: bool,
    /// How the probe's **outer** HTTP/3 connection to a MASQUE proxy is built
    /// (default: `None`).
    ///
    /// [`tunnel_probe`](Self::tunnel_probe) alone is not enough, because trust
    /// anchors are not a detail the pool may guess at. A MASQUE proxy fronted
    /// by a private CA — the normal case for a self-hosted or vendor-issued
    /// deployment — is perfectly healthy, and probing it against the operating
    /// system's certificate store would fail the handshake and feed the
    /// bad-proxy counter. That is a false *negative*: the health checker would
    /// actively blacklist working proxies, which is strictly worse than not
    /// checking them at all.
    ///
    /// So there is no default: with `tunnel_probe` on and this left `None` the
    /// probe is skipped exactly as if `tunnel_probe` were `false`, and a
    /// `warn!` says why. Supplying a config — typically the one the requests
    /// themselves will use, [`Client::masque_config`](crate::Client::masque_config)
    /// — is what turns the probe on for real.
    ///
    /// `bind_addr`, `server_name`, `alpn` and the trust anchors are the parts
    /// that matter here. The tunnel lifecycle knobs (`tunnel_idle_timeout`,
    /// `max_idle_tunnels`) are irrelevant to a probe that closes its one tunnel
    /// immediately, and are ignored.
    #[cfg(feature = "masque")]
    pub masque_outer_config: Option<crate::proxy::MasqueOuterConfig>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            target_host: "www.google.com".into(),
            target_port: 443,
            #[cfg(feature = "masque")]
            tunnel_probe: false,
            #[cfg(feature = "masque")]
            masque_outer_config: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`ProxyPool`].
pub struct ProxyPoolBuilder {
    proxies: Vec<ProxyConfig>,
    max_proxies: usize,
    rotation: RotationStrategy,
    bad_proxy_config: BadProxyConfig,
    health_check: Option<HealthCheckConfig>,
    custom_provider: Option<Box<dyn ProxyProvider>>,
    buffer_capacity: Option<usize>,
}

impl ProxyPoolBuilder {
    pub(crate) fn new() -> Self {
        Self {
            proxies: Vec::new(),
            max_proxies: 100,
            rotation: RotationStrategy::RoundRobin,
            bad_proxy_config: BadProxyConfig::default(),
            health_check: None,
            custom_provider: None,
            buffer_capacity: None,
        }
    }

    /// Set the proxy list (creates a [`ProxyRotator`] internally).
    ///
    /// This is the classic API for fixed proxy lists.  Combine with
    /// [`rotation()`](Self::rotation) to control the selection strategy.
    pub fn proxies(mut self, proxies: Vec<ProxyConfig>) -> Self {
        self.proxies = proxies;
        self
    }

    /// Set the maximum number of concurrent proxy permits (default: 100).
    pub fn max_proxies(mut self, n: usize) -> Self {
        self.max_proxies = n;
        self
    }

    /// Set the proxy rotation strategy (default: RoundRobin).
    ///
    /// Only applies when using `.proxies()`.  Ignored if a custom
    /// provider is set via `.proxy_provider()` or `.proxy_fn()`.
    pub fn rotation(mut self, strategy: RotationStrategy) -> Self {
        self.rotation = strategy;
        self
    }

    /// Configure the bad-proxy detection mechanism.
    pub fn bad_proxy_config(mut self, config: BadProxyConfig) -> Self {
        self.bad_proxy_config = config;
        self
    }

    /// Enable active proxy health checking.
    ///
    /// `masque://` proxies are skipped by the TCP probe. Probing them for real
    /// needs both `HealthCheckConfig::tunnel_probe` and
    /// `HealthCheckConfig::masque_outer_config` (the `masque` feature); the
    /// outer config is normally the one the requests themselves use, from
    /// `Client::masque_config()`.
    pub fn health_check(mut self, config: HealthCheckConfig) -> Self {
        self.health_check = Some(config);
        self
    }

    /// Set a custom [`ProxyProvider`] implementation.
    ///
    /// This overrides any proxy list set via `.proxies()`.  Use this for
    /// advanced proxy selection logic (geo-routing, weighted selection, etc.).
    pub fn proxy_provider(mut self, provider: impl ProxyProvider + 'static) -> Self {
        self.custom_provider = Some(Box::new(provider));
        self
    }

    /// Set a closure-based proxy provider.
    ///
    /// The closure is called each time a new proxy is needed.  It should
    /// return a proxy URL string (e.g.
    /// `"http://user-sid-123:pass@gateway.com:7777"`).
    ///
    /// This is a convenience wrapper around
    /// [`FnProxyProvider`].
    pub fn proxy_fn(mut self, f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.custom_provider = Some(Box::new(FnProxyProvider::new(f)));
        self
    }

    /// Enable proxy config pre-generation with a buffer of the given capacity.
    ///
    /// A background thread will continuously call the provider's `next_proxy()`
    /// to fill a buffer of pre-generated `ProxyConfig`s.  When [`acquire()`](ProxyPool::acquire)
    /// needs a proxy, it pops from the buffer instead of generating on the fly.
    ///
    /// Most useful with dynamic providers (`.proxy_fn()`) where the generation
    /// might involve expensive computation.
    pub fn proxy_buffer(mut self, capacity: usize) -> Self {
        self.buffer_capacity = Some(capacity);
        self
    }

    /// Build the `ProxyPool`.
    pub fn build(self) -> ProxyPool {
        let provider: Box<dyn ProxyProvider> = if let Some(p) = self.custom_provider {
            p
        } else {
            Box::new(ProxyRotator::new(self.proxies, self.rotation))
        };

        let provider: Box<dyn ProxyProvider> = if let Some(cap) = self.buffer_capacity {
            Box::new(BufferedProxyProvider::new(provider, cap))
        } else {
            provider
        };

        let inner = Arc::new(ProxyPoolInner {
            proxy_provider: provider,
            semaphore: Arc::new(Semaphore::new(self.max_proxies)),
            max_proxies: self.max_proxies,
            cooldown: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            permanently_removed: Mutex::new(HashSet::new()),
            cooldown_counts: Mutex::new(HashMap::new()),
            bad_proxy_config: self.bad_proxy_config,
            health_check: self.health_check,
            shutdown: AtomicBool::new(false),
        });

        ProxyPool::spawn_maintenance_task(Arc::clone(&inner));

        ProxyPool { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(url: &str) -> ProxyConfig {
        ProxyConfig::parse(url).expect("valid proxy url")
    }

    /// Yield to the runtime until `pred` holds or we exhaust the budget.
    /// `record_bad_proxy` does its work on a spawned task, so observable state
    /// only settles after the current task yields a few times.
    async fn yield_until(mut pred: impl FnMut() -> bool) -> bool {
        for _ in 0..2000 {
            if pred() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        pred()
    }

    #[test]
    fn bad_proxy_config_has_sane_defaults() {
        let c = BadProxyConfig::default();
        assert_eq!(c.failure_threshold, 3);
        assert_eq!(c.window, Duration::from_secs(60));
        assert_eq!(c.cooldown_duration, Duration::from_secs(300));
        assert_eq!(c.max_cooldowns, 5);
    }

    #[test]
    fn health_check_config_has_sane_defaults() {
        let c = HealthCheckConfig::default();
        assert_eq!(c.interval, Duration::from_secs(60));
        assert_eq!(c.timeout, Duration::from_secs(5));
        assert_eq!(c.target_host, "www.google.com");
        assert_eq!(c.target_port, 443);
        #[cfg(feature = "masque")]
        {
            assert!(
                !c.tunnel_probe,
                "a CONNECT-UDP probe costs a QUIC handshake per proxy per round; \
                 MASQUE proxies are skipped until it is asked for"
            );
            assert!(
                c.masque_outer_config.is_none(),
                "there is no safe default outer config: guessing one would blacklist \
                 every proxy fronted by a private CA"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Health checks
    // -----------------------------------------------------------------------

    /// A health check aimed at a loopback port nothing listens on: Tier-0, and
    /// a TCP proxy probed against it fails immediately with a refusal.
    ///
    /// MASQUE proxies are skipped by this one — no `tunnel_probe`.
    fn health_check_config() -> HealthCheckConfig {
        HealthCheckConfig {
            interval: Duration::from_secs(3600),
            timeout: Duration::from_millis(500),
            target_host: "127.0.0.1".into(),
            target_port: 1,
            #[cfg(feature = "masque")]
            tunnel_probe: false,
            #[cfg(feature = "masque")]
            masque_outer_config: None,
        }
    }

    /// The same, with the CONNECT-UDP probe armed: flag on *and* an outer
    /// config supplied, which is what it takes to actually probe.
    #[cfg(feature = "masque")]
    fn health_check_config_with_tunnel_probe() -> HealthCheckConfig {
        HealthCheckConfig {
            tunnel_probe: true,
            masque_outer_config: Some(crate::proxy::MasqueOuterConfig::default()),
            ..health_check_config()
        }
    }

    /// `tunnel_probe` asked for, but nothing said how to build the outer
    /// connection: the probe has no trust anchors it may assume, so it must
    /// skip rather than guess.
    #[cfg(feature = "masque")]
    fn health_check_config_tunnel_probe_without_outer_config() -> HealthCheckConfig {
        HealthCheckConfig {
            tunnel_probe: true,
            ..health_check_config()
        }
    }

    /// Health-check failures land in the sliding window and nowhere else, so
    /// this is what "the checker blamed this proxy" looks like from inside.
    async fn recorded_failures(pool: &ProxyPool, identity: &str) -> usize {
        pool.inner
            .failures
            .lock()
            .await
            .get(identity)
            .map_or(0, |entries| entries.len())
    }

    /// A MASQUE proxy address nothing is listening on, in either protocol.
    #[cfg(feature = "masque")]
    fn dead_masque() -> ProxyConfig {
        proxy("masque://127.0.0.1:1")
    }

    #[tokio::test]
    #[cfg(feature = "masque")]
    async fn health_check_skips_masque_proxies_by_default() {
        // The MASQUE proxy does not exist at all. A TCP probe would still have
        // something to say about it, and whatever it said would be worthless —
        // so nothing may be said. The HTTP proxy next to it is the control: it
        // is equally dead and must still be blamed, unchanged.
        let masque = dead_masque();
        let http = proxy("http://127.0.0.1:1");
        let (masque_id, http_id) = (masque.identity(), http.identity());
        let pool = ProxyPool::builder().proxies(vec![masque, http]).build();

        run_health_checks(&pool.inner, &health_check_config()).await;

        assert_eq!(
            recorded_failures(&pool, &masque_id).await,
            0,
            "a skipped MASQUE proxy must not be blamed by the active checker"
        );
        assert_eq!(
            recorded_failures(&pool, &http_id).await,
            1,
            "the non-MASQUE path must keep recording failures exactly as before"
        );
        assert!(
            pool.inner.permanently_removed.lock().await.is_empty(),
            "a single health check never removes anything"
        );
        assert!(pool.inner.cooldown.lock().await.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "masque")]
    async fn skipped_masque_proxy_keeps_its_cooldown() {
        // Skipping means "no opinion": a skipped proxy must not be credited out
        // of cooldown either, or an unreachable MASQUE proxy would be released
        // every round.
        let masque = dead_masque();
        let id = masque.identity();
        let pool = ProxyPool::builder().proxies(vec![masque]).build();
        let expires = Instant::now() + Duration::from_secs(300);
        pool.inner.cooldown.lock().await.insert(id.clone(), expires);

        run_health_checks(&pool.inner, &health_check_config()).await;

        assert_eq!(
            pool.inner.cooldown.lock().await.get(&id).copied(),
            Some(expires),
            "a skipped MASQUE proxy must stay in cooldown"
        );
        assert_eq!(recorded_failures(&pool, &id).await, 0);
    }

    /// A one-shot HTTP CONNECT proxy that answers `200` and nothing else.
    async fn spawn_connect_stub() -> (ProxyConfig, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte).await {
                    Ok(1) => request.push(byte[0]),
                    _ => return,
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
            // Leave the tunnel open until the probe drops its end.
            let _ = stream.read(&mut byte).await;
        });
        (proxy(&format!("http://{addr}")), task)
    }

    #[tokio::test]
    async fn health_check_still_recovers_a_reachable_tcp_proxy_from_cooldown() {
        // Non-MASQUE control for the success path: a proxy that completes the
        // CONNECT exchange is healthy, and a healthy proxy is lifted out of
        // cooldown — behaviour the MASQUE branch must not have disturbed.
        let (p, stub) = spawn_connect_stub().await;
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id.clone(), Instant::now() + Duration::from_secs(300));

        run_health_checks(&pool.inner, &health_check_config()).await;

        assert_eq!(recorded_failures(&pool, &id).await, 0);
        assert!(
            !pool.inner.cooldown.lock().await.contains_key(&id),
            "a healthy TCP proxy is recovered from cooldown"
        );
        stub.abort();
    }

    #[cfg(feature = "masque")]
    #[tokio::test]
    async fn tunnel_probe_does_not_disturb_a_reachable_tcp_proxy() {
        // The same control with the flag on: `tunnel_probe` is a MASQUE-only
        // switch and must not reach the TCP path at all.
        let (p, stub) = spawn_connect_stub().await;
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id.clone(), Instant::now() + Duration::from_secs(300));

        run_health_checks(&pool.inner, &health_check_config_with_tunnel_probe()).await;

        assert_eq!(recorded_failures(&pool, &id).await, 0);
        assert!(!pool.inner.cooldown.lock().await.contains_key(&id));
        stub.abort();
    }

    #[cfg(feature = "masque")]
    #[tokio::test]
    async fn tunnel_probe_blames_an_unreachable_masque_proxy_within_the_timeout() {
        // With the probe on, the same nonexistent proxy is now judged — and the
        // verdict must arrive inside `HealthCheckConfig::timeout`, which wraps
        // DNS, the outer QUIC handshake and the CONNECT-UDP exchange together.
        let masque = dead_masque();
        let http = proxy("http://127.0.0.1:1");
        let (masque_id, http_id) = (masque.identity(), http.identity());
        let pool = ProxyPool::builder().proxies(vec![masque, http]).build();

        let started = Instant::now();
        run_health_checks(&pool.inner, &health_check_config_with_tunnel_probe()).await;
        let elapsed = started.elapsed();

        assert_eq!(
            recorded_failures(&pool, &masque_id).await,
            1,
            "an unreachable MASQUE proxy must fail its CONNECT-UDP probe"
        );
        assert_eq!(
            recorded_failures(&pool, &http_id).await,
            1,
            "turning the tunnel probe on must not change the non-MASQUE path"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the probe must be bounded by config.timeout, took {elapsed:?}"
        );
    }

    #[cfg(feature = "masque")]
    #[tokio::test]
    async fn tunnel_probe_without_an_outer_config_skips_instead_of_blaming() {
        // `tunnel_probe` on, `masque_outer_config` unset. The proxy here is
        // unreachable, so a probe *would* have blamed it — which is exactly
        // what makes this a statement about the missing config rather than
        // about the proxy. Without trust anchors the probe cannot distinguish
        // "dead" from "fronted by a CA I was never told about", so it must say
        // nothing at all. The HTTP proxy is the control: the missing MASQUE
        // config must not disarm the TCP path.
        let masque = dead_masque();
        let http = proxy("http://127.0.0.1:1");
        let (masque_id, http_id) = (masque.identity(), http.identity());
        let pool = ProxyPool::builder().proxies(vec![masque, http]).build();
        let expires = Instant::now() + Duration::from_secs(300);
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(masque_id.clone(), expires);

        run_health_checks(
            &pool.inner,
            &health_check_config_tunnel_probe_without_outer_config(),
        )
        .await;

        assert_eq!(
            recorded_failures(&pool, &masque_id).await,
            0,
            "a probe with no trust anchors must not blame the proxy it could not verify"
        );
        assert_eq!(
            pool.inner.cooldown.lock().await.get(&masque_id).copied(),
            Some(expires),
            "skipping means no opinion: the proxy is not credited out of cooldown either"
        );
        assert_eq!(
            recorded_failures(&pool, &http_id).await,
            1,
            "the non-MASQUE path is unaffected by the missing outer config"
        );
    }

    #[tokio::test]
    async fn builder_reports_max_concurrent() {
        let pool = ProxyPool::builder()
            .proxies(vec![proxy("http://a.example.com:8080")])
            .max_proxies(7)
            .rotation(RotationStrategy::RoundRobin)
            .build();
        assert_eq!(pool.max_concurrent(), 7);
    }

    #[tokio::test]
    async fn acquire_returns_a_proxy_from_a_static_list() {
        let proxies = vec![
            proxy("http://a.example.com:8080"),
            proxy("http://b.example.com:8080"),
        ];
        let identities: HashSet<String> = proxies.iter().map(|p| p.identity()).collect();
        let pool = ProxyPool::builder().proxies(proxies).build();

        let guard = pool.acquire().await;
        let got = guard.proxy().expect("static list yields a proxy");
        assert!(identities.contains(&got.identity()));
    }

    #[tokio::test]
    async fn acquire_yields_none_for_empty_list() {
        let pool = ProxyPool::builder().proxies(vec![]).build();
        let guard = pool.acquire().await;
        assert!(guard.proxy().is_none(), "empty list => direct connection");
    }

    #[tokio::test]
    async fn dropping_a_guard_releases_its_permit() {
        // Capacity of one: the second acquire can only succeed after the first
        // guard is dropped and its permit returns to the semaphore.
        let pool = ProxyPool::builder()
            .proxies(vec![proxy("http://a.example.com:8080")])
            .max_proxies(1)
            .build();

        let g1 = pool.acquire().await;
        assert!(
            pool.inner.semaphore.try_acquire().is_err(),
            "permit is held"
        );
        drop(g1);
        let _g2 = pool.acquire().await; // would block forever if the permit leaked
    }

    #[tokio::test]
    async fn next_usable_proxy_skips_permanently_removed() {
        let p = proxy("http://only.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();

        pool.inner.permanently_removed.lock().await.insert(id);
        assert!(pool.next_usable_proxy().await.is_none());
    }

    #[tokio::test]
    async fn next_usable_proxy_skips_only_while_in_cooldown() {
        let p = proxy("http://only.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();

        // Future expiry => still cooling down => skipped.
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id.clone(), Instant::now() + Duration::from_secs(60));
        assert!(pool.next_usable_proxy().await.is_none());

        // Past expiry => recovered => returned again.
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id, Instant::now() - Duration::from_secs(1));
        assert!(pool.next_usable_proxy().await.is_some());
    }

    #[tokio::test]
    async fn dynamic_provider_ignores_bad_proxy_marks() {
        let pool = ProxyPool::builder()
            .proxy_fn(|| "http://user:pass@gateway.example.com:7777".to_string())
            .build();

        // Dynamic identities are ephemeral, so marking is a no-op: nothing should
        // ever land in the cooldown map.
        pool.mark_bad_proxy("http://user:pass@gateway.example.com:7777");
        // Give any (erroneously) spawned task a chance to run, then confirm
        // nothing ever landed in the cooldown map.
        yield_until(|| false).await;
        assert!(pool.inner.cooldown.try_lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn repeated_failures_move_a_proxy_through_cooldown_then_removal() {
        let p = proxy("http://flaky.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder()
            .proxies(vec![p])
            .bad_proxy_config(BadProxyConfig {
                failure_threshold: 3,
                window: Duration::from_secs(60),
                cooldown_duration: Duration::from_secs(300),
                max_cooldowns: 2,
            })
            .build();

        // First 3 failures within the window => one cooldown.
        for _ in 0..3 {
            pool.mark_bad_proxy(&id);
        }
        let cooled = {
            let id = id.clone();
            let pool = pool.clone();
            yield_until(move || {
                pool.inner
                    .cooldown
                    .try_lock()
                    .is_ok_and(|m| m.contains_key(&id))
            })
            .await
        };
        assert!(cooled, "threshold failures should trigger a cooldown");

        // 3 more failures => second cooldown reaches max_cooldowns => permanent removal.
        for _ in 0..3 {
            pool.mark_bad_proxy(&id);
        }
        let removed = {
            let id = id.clone();
            let pool = pool.clone();
            yield_until(move || {
                pool.inner
                    .permanently_removed
                    .try_lock()
                    .is_ok_and(|s| s.contains(&id))
            })
            .await
        };
        assert!(
            removed,
            "max_cooldowns reached should permanently remove the proxy"
        );
    }
}
