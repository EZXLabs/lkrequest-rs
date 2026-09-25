use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::{Error, Result};

/// Configuration for a proxy (optionally a multi-hop **proxychain**).
///
/// `scheme`/`auth` describe the **final** hop — the proxy that connects to the
/// target. `chain` holds the upstream hops traversed *before* it (client→…);
/// an empty `chain` is an ordinary single proxy. The full path is
/// `chain[0] → chain[1] → … → self → target`, each hop CONNECT-tunneled over
/// the previous hop's stream. Build chains with
/// [`parse_chain`](ProxyConfig::parse_chain) or [`through`](ProxyConfig::through).
///
/// **TCP (H1/H2)** chains work with any mix of HTTP and SOCKS5 hops. **QUIC/H3**
/// chains additionally work, but require *every* hop to be SOCKS5: the transport
/// is carried over nested SOCKS5 UDP ASSOCIATE (one UDP relay per hop, stacked
/// as nested per-datagram headers), which HTTP CONNECT cannot provide. A QUIC
/// request over a chain containing an HTTP hop errors; fall back to H2.
///
/// # Constructing one
///
/// This struct is `#[non_exhaustive]`: a struct literal does not compile
/// outside this crate. Proxy authentication is still an open-ended area — the
/// `credential` and `auth_header` fields were themselves added after the
/// initial release, and challenge-based schemes will need more — so the type is
/// sealed against literals to keep the next field from being a breaking change
/// for every downstream crate.
///
/// Build one of these instead, then layer the rest on with the chaining
/// setters:
///
/// - [`ProxyConfig::parse`] / [`parse_chain`](Self::parse_chain) for a URL
///   (the usual entry point),
/// - [`ProxyConfig::new`] for a [`ProxyScheme`] you already hold.
///
/// ```
/// use lkrequest::proxy::{ProxyAuthHeader, ProxyConfig, ProxyScheme};
///
/// let proxy = ProxyConfig::new(ProxyScheme::Http {
///     host: "proxy.example.com".to_string(),
///     port: 443,
/// })
/// .with_http_auth("Preshared", "<psk>")
/// .unwrap()
/// .with_auth_header(ProxyAuthHeader::Authorization);
/// ```
///
/// There is deliberately no `Default`: every [`ProxyScheme`] carries a host and
/// a port, and there is no address that could stand in for them without
/// inventing one.
///
/// The fields stay public and readable/writable — sealing only applies to
/// literals, so existing `config.auth = …` style mutation keeps working.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// The proxy protocol and address.
    pub scheme: ProxyScheme,
    /// Optional username/password credentials.
    ///
    /// This is the original, still-supported entry point and is exactly
    /// equivalent to [`ProxyCredential::UserPass`]: HTTP-header proxies encode
    /// it as `Basic`, SOCKS5 runs the RFC 1929 sub-negotiation. Setting it is
    /// sugar for setting `credential` to `UserPass`; setting **both** `auth`
    /// and `credential` is rejected by [`validate`](Self::validate) so the
    /// effective credential is never ambiguous.
    pub auth: Option<ProxyAuth>,
    /// Non-username/password credentials (static HTTP auth scheme, or a custom
    /// authenticator).
    ///
    /// Leave `None` and use [`auth`](Self::auth) for username/password. Use
    /// [`with_http_auth`](Self::with_http_auth) /
    /// [`with_custom_auth`](Self::with_custom_auth) to set it with validation.
    pub credential: Option<ProxyCredential>,
    /// Which request header carries HTTP-based proxy credentials.
    ///
    /// Defaults to `Proxy-Authorization`. Ignored by SOCKS5, which has no
    /// header-based authentication.
    pub auth_header: ProxyAuthHeader,
    /// Upstream hops to traverse before reaching this proxy (proxychain).
    ///
    /// Ordered client→…; empty means a direct connection to this proxy. Each
    /// entry is itself a single hop (its own `chain` is ignored).
    pub chain: Vec<ProxyConfig>,
}

/// Proxy protocol type.
#[derive(Debug, Clone)]
pub enum ProxyScheme {
    /// HTTP CONNECT proxy.
    Http {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port.
        port: u16,
    },
    /// SOCKS5 proxy (remote DNS — the proxy resolves the hostname).
    Socks5 {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port.
        port: u16,
        /// If `true`, the proxy resolves the target hostname (socks5h).
        /// If `false`, local DNS resolution is done first (socks5).
        remote_dns: bool,
    },
    /// MASQUE proxy (RFC 9298 CONNECT-UDP over HTTP/3).
    ///
    /// Relays **UDP only**: it carries QUIC/HTTP3 and cannot carry TCP, so
    /// HTTP/1.1 and HTTP/2 requests through it fail explicitly rather than
    /// falling back to a direct connection. The proxy resolves the target
    /// hostname (the target is encoded in the request path, RFC 9298 §3.1), so
    /// this route is remote-DNS like `socks5h`.
    ///
    /// Requires the `masque` feature (which implies `quic-h3`). Without it the
    /// variant does not exist at all: there is no tunnel layer to carry the
    /// route, so a `masque://` URL is rejected by [`ProxyConfig::parse`]
    /// instead of parsing into a scheme that is guaranteed to fail later.
    #[cfg(feature = "masque")]
    Masque {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port.
        port: u16,
    },
}

impl ProxyScheme {
    /// Whether this is a MASQUE (RFC 9298 CONNECT-UDP) proxy.
    ///
    /// Exists so the callers that only need the yes/no answer keep one shape
    /// across feature combinations: without the `masque` feature the variant
    /// does not exist, and `matches!(…, ProxyScheme::Masque { .. })` would not
    /// compile. Here it is a constant `false` instead.
    pub(crate) fn is_masque(&self) -> bool {
        #[cfg(feature = "masque")]
        {
            matches!(self, ProxyScheme::Masque { .. })
        }
        #[cfg(not(feature = "masque"))]
        {
            false
        }
    }
}

/// Proxy authentication credentials (username/password).
///
/// Retained as the username/password entry point; it is the constructor sugar
/// for [`ProxyCredential::UserPass`] and converts into it via [`From`].
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    /// Proxy username.
    pub username: String,
    /// Proxy password.
    pub password: String,
}

/// Which header carries HTTP-based proxy credentials.
///
/// There is no interoperable answer here: Bright Data, Cloudflare and gost use
/// `Proxy-Authorization`, while masque-go's documented example and RFC 9484 §11
/// use `Authorization`. RFC 9298 itself does not specify authentication at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyAuthHeader {
    /// `Proxy-Authorization` (default).
    #[default]
    ProxyAuthorization,
    /// `Authorization`.
    Authorization,
}

impl ProxyAuthHeader {
    /// The header field name this variant selects.
    pub fn header_name(self) -> &'static str {
        match self {
            ProxyAuthHeader::ProxyAuthorization => "Proxy-Authorization",
            ProxyAuthHeader::Authorization => "Authorization",
        }
    }
}

/// A custom proxy authentication algorithm.
///
/// The extension point for schemes that must compute credentials at request
/// time (Digest, Privacy Pass redemption, …). Rust-only: trait objects cannot
/// cross the C ABI, so this variant has no FFI equivalent.
pub trait ProxyAuthenticator: Send + Sync + 'static {
    /// A stable, non-secret fragment that distinguishes this credential from
    /// another one configured on the *same* proxy address.
    ///
    /// This participates in [`ProxyConfig::identity`]. Returning a constant
    /// makes two proxies that share an address but not credentials collapse
    /// onto one cooldown/blacklist key, so one failing proxy would blacklist
    /// the other.
    fn identity_fragment(&self) -> String;

    /// The authorization header **value** to send (e.g. `"Bearer abc123"`), or
    /// `None` to send no credentials on this attempt.
    fn authorization_value(&self) -> Option<String>;
}

/// The credential a proxy authenticates with.
#[derive(Clone)]
pub enum ProxyCredential {
    /// Username and password.
    ///
    /// HTTP-header proxies encode it as `Basic`; SOCKS5 runs the RFC 1929
    /// binary sub-negotiation.
    UserPass {
        /// Proxy username.
        username: String,
        /// Proxy password.
        password: String,
    },
    /// A static HTTP authentication scheme plus already-encoded credentials
    /// (`Preshared`, `PrivateToken`, `Bearer`, …).
    ///
    /// Header-based only. Configuring it on a SOCKS5 proxy is a configuration
    /// error and is rejected by [`ProxyConfig::validate`] rather than silently
    /// ignored — SOCKS5 has no way to carry it.
    Http {
        /// The auth-scheme token, e.g. `"Preshared"`.
        scheme: String,
        /// The credentials that follow the scheme token, already encoded.
        credentials: String,
    },
    /// A custom authenticator (Rust-only).
    Custom(Arc<dyn ProxyAuthenticator>),
}

impl fmt::Debug for ProxyCredential {
    /// Hand-written so `ProxyConfig` keeps its `Debug` (a `dyn` authenticator
    /// cannot derive it) and so secrets never reach logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyCredential::UserPass { username, .. } => f
                .debug_struct("UserPass")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            ProxyCredential::Http { scheme, .. } => f
                .debug_struct("Http")
                .field("scheme", scheme)
                .field("credentials", &"<redacted>")
                .finish(),
            ProxyCredential::Custom(auth) => f
                .debug_tuple("Custom")
                .field(&auth.identity_fragment())
                .finish(),
        }
    }
}

impl From<ProxyAuth> for ProxyCredential {
    fn from(auth: ProxyAuth) -> Self {
        ProxyCredential::UserPass {
            username: auth.username,
            password: auth.password,
        }
    }
}

impl ProxyCredential {
    /// The username/password pair, if this credential is one.
    pub fn user_pass(&self) -> Option<(&str, &str)> {
        match self {
            ProxyCredential::UserPass { username, password } => {
                Some((username.as_str(), password.as_str()))
            }
            _ => None,
        }
    }

    /// The authorization header **value** for header-based proxies, or `None`
    /// when this credential produces none.
    pub fn authorization_value(&self) -> Option<String> {
        match self {
            ProxyCredential::UserPass { username, password } => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}").as_bytes());
                Some(format!("Basic {encoded}"))
            }
            ProxyCredential::Http {
                scheme,
                credentials,
            } => Some(format!("{scheme} {credentials}")),
            ProxyCredential::Custom(auth) => auth.authorization_value(),
        }
    }

    /// A stable, non-secret fragment identifying this credential.
    ///
    /// Passwords and encoded credentials are never returned verbatim: the
    /// secret-bearing forms contribute an opaque in-process fingerprint so that
    /// distinct credentials stay distinguishable without the identity string
    /// becoming a place secrets leak from.
    fn identity_fragment(&self) -> String {
        match self {
            // Unchanged from the pre-`ProxyCredential` encoding: the username
            // identifies the session, the password is deliberately excluded.
            ProxyCredential::UserPass { username, .. } => format!("user:{username}"),
            ProxyCredential::Http {
                scheme,
                credentials,
            } => format!("http:{scheme}:{}", opaque_fingerprint(credentials)),
            ProxyCredential::Custom(auth) => format!("custom:{}", auth.identity_fragment()),
        }
    }
}

/// A short, deterministic, non-reversible fingerprint of a secret.
///
/// Only ever used as an in-process map key; it is not a security primitive and
/// its exact value is not stable across builds.
fn opaque_fingerprint(secret: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    secret.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

impl ProxyConfig {
    /// A single-hop proxy on `scheme`, with no credentials and no chain.
    ///
    /// The constructor entry point for code that already holds a
    /// [`ProxyScheme`]; [`parse`](Self::parse) is the one to reach for when you
    /// have a URL. `ProxyConfig` is `#[non_exhaustive]`, so one of these two is
    /// required — a struct literal does not compile outside this crate.
    ///
    /// Add credentials and hops with the chaining setters:
    /// [`with_user_pass`](Self::with_user_pass),
    /// [`with_http_auth`](Self::with_http_auth),
    /// [`with_custom_auth`](Self::with_custom_auth),
    /// [`with_auth_header`](Self::with_auth_header) and
    /// [`through`](Self::through).
    ///
    /// ```
    /// use lkrequest::proxy::{ProxyConfig, ProxyScheme};
    ///
    /// let proxy = ProxyConfig::new(ProxyScheme::Socks5 {
    ///     host: "127.0.0.1".to_string(),
    ///     port: 1080,
    ///     remote_dns: true,
    /// })
    /// .with_user_pass("user", "pass")
    /// .unwrap();
    /// assert_eq!(proxy.to_string(), "socks5h://127.0.0.1:1080");
    /// ```
    pub fn new(scheme: ProxyScheme) -> Self {
        Self {
            scheme,
            auth: None,
            credential: None,
            auth_header: ProxyAuthHeader::default(),
            chain: Vec::new(),
        }
    }

    /// Parse a proxy URL string.
    ///
    /// Supported formats:
    /// - `http://host:port`
    /// - `http://user:pass@host:port`
    /// - `https://host:port`
    /// - `socks5://host:port`
    /// - `socks5://user:pass@host:port`
    /// - `masque://host[:port]` (RFC 9298 CONNECT-UDP; port defaults to 443)
    /// - `masque://user:pass@host:port`
    ///
    /// The two `masque://` forms need the `masque` feature (which implies
    /// `quic-h3`). Without it there is no CONNECT-UDP client to carry the
    /// route, so they are rejected here with an error naming the feature
    /// rather than parsing into a proxy every request would fail on.
    ///
    /// URLs can only express username/password credentials. For
    /// `Preshared`/`PrivateToken`/`Bearer`-style credentials, parse the URL and
    /// then call [`with_http_auth`](Self::with_http_auth).
    pub fn parse(url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url)
            .map_err(|e| Error::InvalidConfig(format!("invalid proxy URL '{url}': {e}")))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidConfig(format!("proxy URL missing host: '{url}'")))?
            .to_string();

        let auth = if !parsed.username().is_empty() {
            Some(ProxyAuth {
                username: percent_decode(parsed.username()),
                password: percent_decode(parsed.password().unwrap_or("")),
            })
        } else {
            None
        };

        let scheme = match parsed.scheme() {
            "http" | "https" => {
                let port = parsed.port_or_known_default().ok_or_else(|| {
                    Error::InvalidConfig(format!("proxy URL missing port: '{url}'"))
                })?;
                ProxyScheme::Http { host, port }
            }
            "socks5" | "socks5h" => {
                let port = parsed.port().unwrap_or(1080);
                let remote_dns = parsed.scheme() == "socks5h";
                ProxyScheme::Socks5 {
                    host,
                    port,
                    remote_dns,
                }
            }
            // RFC 9298 rides HTTP/3, whose default port is 443.
            #[cfg(feature = "masque")]
            "masque" => {
                let port = parsed.port().unwrap_or(443);
                ProxyScheme::Masque { host, port }
            }
            // Without the feature there is no CONNECT-UDP client to carry the
            // route, so refuse here rather than accepting a configuration that
            // is certain to fail on the first request: the user finds out while
            // configuring the proxy, not once traffic depends on it.
            #[cfg(not(feature = "masque"))]
            "masque" => {
                return Err(Error::InvalidConfig(format!(
                    "proxy URL '{url}' uses the `masque` scheme (RFC 9298 CONNECT-UDP), but this \
                     build of lkrequest was compiled without the `masque` feature; rebuild with \
                     `--features masque` (it implies `quic-h3`)"
                )))
            }
            other => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported proxy scheme '{other}' (expected http, https, socks5, masque)"
                )))
            }
        };

        let mut config = ProxyConfig::new(scheme);
        config.auth = auth;
        config.validate()?;
        Ok(config)
    }

    /// Replace this proxy's credentials with a username/password pair.
    pub fn with_user_pass(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        self.auth = Some(ProxyAuth {
            username: username.into(),
            password: password.into(),
        });
        self.credential = None;
        self.validate()?;
        Ok(self)
    }

    /// Authenticate with a static HTTP auth-scheme and already-encoded
    /// credentials, e.g. `with_http_auth("Preshared", "<psk>")`.
    ///
    /// Errors when this proxy is SOCKS5: there is no way to carry a header
    /// credential in the SOCKS5 handshake, so accepting it would build a
    /// configuration that can only fail at connect time.
    pub fn with_http_auth(
        mut self,
        scheme: impl Into<String>,
        credentials: impl Into<String>,
    ) -> Result<Self> {
        self.auth = None;
        self.credential = Some(ProxyCredential::Http {
            scheme: scheme.into(),
            credentials: credentials.into(),
        });
        self.validate()?;
        Ok(self)
    }

    /// Authenticate with a custom [`ProxyAuthenticator`] (Rust-only).
    pub fn with_custom_auth(mut self, authenticator: Arc<dyn ProxyAuthenticator>) -> Result<Self> {
        self.auth = None;
        self.credential = Some(ProxyCredential::Custom(authenticator));
        self.validate()?;
        Ok(self)
    }

    /// Select which header carries HTTP-based credentials.
    pub fn with_auth_header(mut self, header: ProxyAuthHeader) -> Self {
        self.auth_header = header;
        self
    }

    /// The effective credential for this hop, folding the legacy
    /// [`auth`](Self::auth) field into [`ProxyCredential::UserPass`].
    pub fn resolved_credential(&self) -> Option<ProxyCredential> {
        match (&self.credential, &self.auth) {
            (Some(credential), _) => Some(credential.clone()),
            (None, Some(auth)) => Some(auth.clone().into()),
            (None, None) => None,
        }
    }

    /// The username/password pair to use for the SOCKS5 RFC 1929
    /// sub-negotiation, if this proxy has one.
    pub(crate) fn socks5_user_pass(&self) -> Option<ProxyAuth> {
        match self.resolved_credential()? {
            ProxyCredential::UserPass { username, password } => {
                Some(ProxyAuth { username, password })
            }
            _ => None,
        }
    }

    /// The `(header name, header value)` pair for header-based proxy
    /// authentication, if this proxy has credentials that produce one.
    pub fn http_auth_header(&self) -> Option<(&'static str, String)> {
        let value = self.resolved_credential()?.authorization_value()?;
        Some((self.auth_header.header_name(), value))
    }

    /// Validate this configuration (and every chain hop) for combinations that
    /// the runtime could never honour.
    ///
    /// Called by [`parse`](Self::parse), by the `with_*` credential setters and
    /// before connecting, so a bad combination surfaces as a configuration
    /// error instead of a confusing runtime failure.
    pub fn validate(&self) -> Result<()> {
        for hop in &self.chain {
            if hop.scheme.is_masque() {
                return Err(Error::InvalidConfig(format!(
                    "MASQUE proxy {hop} cannot be a proxychain hop: nested tunnels shrink the \
                     usable MTU at every hop, and the inner MTU is already bounded by the outer \
                     datagram limit"
                )));
            }
            hop.validate_hop()?;
        }
        if !self.chain.is_empty() && self.scheme.is_masque() {
            return Err(Error::InvalidConfig(format!(
                "MASQUE proxy {self} cannot be used in a proxychain"
            )));
        }
        self.validate_hop()
    }

    /// Validate a single hop, ignoring its (unused) nested chain.
    fn validate_hop(&self) -> Result<()> {
        if self.auth.is_some() && self.credential.is_some() {
            return Err(Error::InvalidConfig(format!(
                "proxy {self} sets both `auth` and `credential`; set exactly one \
                 (`auth` is sugar for `ProxyCredential::UserPass`)"
            )));
        }
        if matches!(self.scheme, ProxyScheme::Socks5 { .. }) {
            match &self.credential {
                Some(ProxyCredential::Http { scheme, .. }) => {
                    return Err(Error::InvalidConfig(format!(
                        "SOCKS5 proxy {self} cannot use the HTTP '{scheme}' credential: SOCKS5 \
                         authenticates with the RFC 1929 username/password sub-negotiation and \
                         has no request headers — use `auth`/`with_user_pass`, or point this \
                         credential at an HTTP CONNECT or MASQUE proxy"
                    )));
                }
                Some(ProxyCredential::Custom(_)) => {
                    return Err(Error::InvalidConfig(format!(
                        "SOCKS5 proxy {self} cannot use a custom authenticator: custom \
                         authenticators produce an HTTP authorization header value, which SOCKS5 \
                         cannot carry"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Build a **proxychain** from an ordered list of proxy URLs (client→target).
    ///
    /// The last URL is the final hop (connects to the target); earlier URLs are
    /// traversed first. Equivalent to parsing each URL and chaining them.
    ///
    /// ```
    /// use lkrequest::proxy::ProxyConfig;
    /// let chain = ProxyConfig::parse_chain([
    ///     "socks5://hop1:1080",
    ///     "socks5h://hop2:1080",
    /// ]).unwrap();
    /// assert_eq!(chain.hop_count(), 2);
    /// ```
    pub fn parse_chain<I, S>(urls: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut configs: Vec<ProxyConfig> = urls
            .into_iter()
            .map(|u| ProxyConfig::parse(u.as_ref()))
            .collect::<Result<_>>()?;
        let mut last = configs.pop().ok_or_else(|| {
            Error::InvalidConfig("proxy chain must contain at least one proxy".to_string())
        })?;
        // Flatten: ignore any nested chains on the parsed hops (parse() never
        // sets one) and treat the leading configs as the upstream hops.
        last.chain = configs;
        last.validate()?;
        Ok(last)
    }

    /// Prepend `hops` as upstream proxies traversed before this one.
    ///
    /// Resulting path: `hops[0] → … → hops[n-1] → self → target`.
    pub fn through(mut self, hops: Vec<ProxyConfig>) -> Self {
        self.chain = hops;
        self
    }

    /// Number of proxy hops in the path (1 = single proxy, no chain).
    pub fn hop_count(&self) -> usize {
        self.chain.len() + 1
    }

    /// Whether a failure on this route must **never** fall back to a direct
    /// connection, regardless of
    /// [`proxy_fallback_direct`](crate::client::ClientBuilder::proxy_fallback_direct).
    ///
    /// True exactly when a MASQUE hop is involved. MASQUE exists to hide the
    /// client's source address (RFC 9298 CONNECT-UDP), so a silent direct
    /// connection after the tunnel fails would leak the real IP to the target —
    /// the one outcome the user picked MASQUE to avoid. A failure the user can
    /// see is strictly better than a success that deanonymises them, so this
    /// overrides the opt-in rather than deferring to it.
    ///
    /// HTTP CONNECT and SOCKS5 routes return `false` and keep honouring the
    /// switch exactly as before.
    pub fn forbids_direct_fallback(&self) -> bool {
        // MASQUE is rejected as a chain hop by `validate`, but check every hop
        // anyway so the guarantee does not depend on validation having run.
        self.chain
            .iter()
            .chain(std::iter::once(self))
            .any(|hop| hop.scheme.is_masque())
    }

    /// Returns the host and port of this proxy.
    pub fn host_port(&self) -> (&str, u16) {
        match &self.scheme {
            ProxyScheme::Http { host, port } => (host, *port),
            ProxyScheme::Socks5 { host, port, .. } => (host, *port),
            #[cfg(feature = "masque")]
            ProxyScheme::Masque { host, port } => (host, *port),
        }
    }

    /// Returns a synthetic socket address for use as a connection pool key.
    ///
    /// For IP-based proxies this is the real address; for hostname proxies
    /// a placeholder `0.0.0.0:port` is returned (the actual DNS resolution
    /// happens at connect time).
    pub fn addr(&self) -> SocketAddr {
        let (host, port) = self.host_port();
        format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)))
    }

    /// Returns a deterministic identity string for this proxy configuration.
    ///
    /// Unlike [`addr()`](Self::addr) which only considers `host:port`, this
    /// includes the authentication username when present.  This correctly
    /// distinguishes residential-proxy sessions that share the same gateway
    /// address but use different session-ids in the username.
    ///
    /// Used as the key for cooldown / failure tracking in `SessionPool`.
    ///
    /// The identity is an escaped JSON array of ordered hops, including each
    /// hop's protocol, DNS mode, host, port, and a credential fragment.
    /// Nested chains on upstream entries are ignored, just as they are when
    /// connecting.
    ///
    /// The credential fragment is `null` without credentials, `"user:<name>"`
    /// for username/password (the password is intentionally excluded),
    /// `"http:<scheme>:<fingerprint>"` for a static HTTP credential and
    /// `"custom:<fragment>"` for a [`ProxyAuthenticator`]. The non-username
    /// forms have no public component to key on, so they contribute an opaque
    /// fingerprint instead: without it, two proxies sharing an address but not
    /// credentials would collapse onto one key and one failing proxy would
    /// blacklist the other.
    ///
    /// This replaces the legacy delimiter-joined encoding. Treat identities as
    /// opaque keys; use [`Display`](fmt::Display) for human-readable endpoints.
    pub fn identity(&self) -> String {
        let hops: Vec<_> = self
            .chain
            .iter()
            .chain(std::iter::once(self))
            .map(|hop| {
                let scheme = match &hop.scheme {
                    ProxyScheme::Http { .. } => "http",
                    ProxyScheme::Socks5 {
                        remote_dns: false, ..
                    } => "socks5",
                    ProxyScheme::Socks5 {
                        remote_dns: true, ..
                    } => "socks5h",
                    #[cfg(feature = "masque")]
                    ProxyScheme::Masque { .. } => "masque",
                };
                let (host, port) = hop.host_port();
                let credential = hop
                    .resolved_credential()
                    .map(|credential| credential.identity_fragment());
                (scheme, host, port, credential)
            })
            .collect();
        serde_json::to_string(&hops).expect("proxy identity fields are JSON serializable")
    }

    /// Perform a health check by attempting a TCP connection through this proxy.
    ///
    /// Returns the connection latency on success, or an error if the probe fails.
    pub async fn health_check(
        &self,
        target_host: &str,
        target_port: u16,
        timeout: std::time::Duration,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<std::time::Duration> {
        let start = std::time::Instant::now();
        tokio::time::timeout(
            timeout,
            self.connect(target_host, target_port, None, resolver),
        )
        .await
        .map_err(|_| {
            Error::timeout(
                format!(
                    "health check timed out after {:?} for proxy {}",
                    timeout, self
                ),
                Some(crate::error::ConnectionPhase::ProxyTunnel),
                Some(timeout),
            )
        })??;
        Ok(start.elapsed())
    }
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render upstream hops first (each has an empty chain, so this does not
        // recurse further): "hop1 -> hop2 -> finalhop".
        for hop in &self.chain {
            write!(f, "{hop} -> ")?;
        }
        match &self.scheme {
            ProxyScheme::Http { host, port } => write!(f, "http://{}:{}", host, port),
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
            } => {
                let scheme = if *remote_dns { "socks5h" } else { "socks5" };
                write!(f, "{}://{}:{}", scheme, host, port)
            }
            #[cfg(feature = "masque")]
            ProxyScheme::Masque { host, port } => write!(f, "masque://{}:{}", host, port),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> String {
    // Re-use the percent-encoding crate bundled with url
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
}

/// Parse HTTP status code from a status line like "HTTP/1.1 200 Connection Established".
pub(super) fn parse_http_status(line: &str) -> Option<u16> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ProxyConfig::parse -------------------------------------------------

    #[test]
    fn parse_http_proxy() {
        let p = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        match &p.scheme {
            ProxyScheme::Http { host, port } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(*port, 8080);
            }
            _ => panic!("expected Http"),
        }
        assert!(p.auth.is_none());
    }

    #[test]
    fn parse_http_proxy_default_port() {
        let p = ProxyConfig::parse("http://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Http { port, .. } => assert_eq!(*port, 80),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_http_proxy_explicit_default_port() {
        let p = ProxyConfig::parse("http://proxy.example.com:80").unwrap();
        match &p.scheme {
            ProxyScheme::Http { port, .. } => assert_eq!(*port, 80),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_https_proxy_default_port() {
        let p = ProxyConfig::parse("https://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Http { port, .. } => assert_eq!(*port, 443),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_http_proxy_with_auth() {
        let p = ProxyConfig::parse("http://user:pass@proxy.example.com:3128").unwrap();
        let auth = p.auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn parse_http_proxy_percent_encoded_auth() {
        let p = ProxyConfig::parse("http://us%40er:p%23ss@proxy.example.com:3128").unwrap();
        let auth = p.auth.as_ref().unwrap();
        assert_eq!(auth.username, "us@er");
        assert_eq!(auth.password, "p#ss");
    }

    #[test]
    fn parse_socks5_proxy() {
        let p = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
            } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(*port, 1080);
                assert!(!remote_dns);
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5h_proxy() {
        let p = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 { remote_dns, .. } => {
                assert!(*remote_dns);
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5_default_port() {
        let p = ProxyConfig::parse("socks5://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 { port, .. } => assert_eq!(*port, 1080),
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5_with_auth() {
        let p = ProxyConfig::parse("socks5://user:pass@proxy.example.com:1080").unwrap();
        assert!(p.auth.is_some());
    }

    #[test]
    fn parse_invalid_scheme() {
        let result = ProxyConfig::parse("ftp://proxy.example.com:21");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_url() {
        let result = ProxyConfig::parse("not a url");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_string() {
        let result = ProxyConfig::parse("");
        assert!(result.is_err());
    }

    // -- Proxychain ---------------------------------------------------------

    #[test]
    fn parse_chain_orders_hops_client_to_target() {
        let chain = ProxyConfig::parse_chain([
            "socks5://hop1:1080",
            "socks5h://hop2:1081",
            "http://hop3:8080",
        ])
        .unwrap();
        // Final hop (connects to the target) is the last URL.
        assert_eq!(chain.host_port(), ("hop3", 8080));
        assert_eq!(chain.hop_count(), 3);
        // Upstream hops are preserved in client→target order.
        assert_eq!(chain.chain.len(), 2);
        assert_eq!(chain.chain[0].host_port(), ("hop1", 1080));
        assert_eq!(chain.chain[1].host_port(), ("hop2", 1081));
    }

    #[test]
    fn parse_chain_single_url_is_a_plain_proxy() {
        let p = ProxyConfig::parse_chain(["http://only:8080"]).unwrap();
        assert_eq!(p.hop_count(), 1);
        assert!(p.chain.is_empty());
    }

    #[test]
    fn parse_chain_empty_is_error() {
        assert!(ProxyConfig::parse_chain(Vec::<String>::new()).is_err());
    }

    #[test]
    fn through_prepends_upstream_hops() {
        let hop = ProxyConfig::parse("socks5://hop:1080").unwrap();
        let p = ProxyConfig::parse("http://final:8080")
            .unwrap()
            .through(vec![hop]);
        assert_eq!(p.hop_count(), 2);
        assert_eq!(p.chain[0].host_port(), ("hop", 1080));
    }

    #[test]
    fn identity_folds_chain_hops_for_distinct_cooldown_keys() {
        let single = ProxyConfig::parse("http://final:8080").unwrap();
        let chain = ProxyConfig::parse_chain(["socks5://hop:1080", "http://final:8080"]).unwrap();
        assert_ne!(single.identity(), chain.identity());
    }

    #[test]
    fn identity_distinguishes_protocol_and_dns_mode_at_each_hop() {
        let mut identities = std::collections::HashSet::new();
        let mut routes = std::collections::HashSet::new();
        for upstream in ["http://hop:1080", "socks5://hop:1080", "socks5h://hop:1080"] {
            for final_hop in [
                "http://final:8080",
                "socks5://final:8080",
                "socks5h://final:8080",
            ] {
                let proxy = ProxyConfig::parse_chain([upstream, final_hop]).unwrap();
                assert!(
                    identities.insert(proxy.identity()),
                    "{upstream} -> {final_hop}"
                );
                assert!(routes.insert(crate::protocol::RouteKey::from_proxy(Some(&proxy))));
            }
        }
        assert_eq!(identities.len(), 9);
        assert_eq!(routes.len(), 9);
    }

    #[test]
    fn identity_keeps_username_separators_inside_the_hop() {
        let single = ProxyConfig::parse("socks5h://hop%3A1080%3Euser:fixture@final:8080").unwrap();
        let chain =
            ProxyConfig::parse_chain(["http://hop:1080", "socks5h://user:fixture@final:8080"])
                .unwrap();
        assert_ne!(single.identity(), chain.identity());
        assert_ne!(
            crate::protocol::RouteKey::from_proxy(Some(&single)),
            crate::protocol::RouteKey::from_proxy(Some(&chain))
        );
    }

    #[test]
    fn identity_preserves_hop_order_and_username_without_passwords() {
        let first =
            ProxyConfig::parse_chain(["http://a:1080", "socks5h://user:fixture-a@b:8080"]).unwrap();
        let reordered =
            ProxyConfig::parse_chain(["socks5h://user:fixture-a@b:8080", "http://a:1080"]).unwrap();
        let changed_user =
            ProxyConfig::parse_chain(["http://a:1080", "socks5h://other:fixture-a@b:8080"])
                .unwrap();
        let changed_password =
            ProxyConfig::parse_chain(["http://a:1080", "socks5h://user:fixture-b@b:8080"]).unwrap();
        assert_ne!(first.identity(), reordered.identity());
        assert_ne!(first.identity(), changed_user.identity());
        assert_eq!(first.identity(), changed_password.identity());
        assert!(!first.identity().contains("fixture-a"));
        assert!(!changed_password.identity().contains("fixture-b"));
    }

    // -- ProxyConfig::new ---------------------------------------------------

    #[test]
    fn new_builds_an_unauthenticated_single_hop() {
        let p = ProxyConfig::new(ProxyScheme::Http {
            host: "proxy.example.com".to_string(),
            port: 8080,
        });
        assert!(p.auth.is_none());
        assert!(p.credential.is_none());
        assert_eq!(p.auth_header, ProxyAuthHeader::ProxyAuthorization);
        assert_eq!(p.hop_count(), 1);
        assert_eq!(p.to_string(), "http://proxy.example.com:8080");
        p.validate().unwrap();
    }

    #[test]
    fn new_plus_setters_matches_the_equivalent_url() {
        let built = ProxyConfig::new(ProxyScheme::Socks5 {
            host: "proxy.example.com".to_string(),
            port: 1080,
            remote_dns: true,
        })
        .with_user_pass("user", "fixture")
        .unwrap();
        let parsed = ProxyConfig::parse("socks5h://user:fixture@proxy.example.com:1080").unwrap();
        assert_eq!(built.identity(), parsed.identity());
        assert_eq!(built.to_string(), parsed.to_string());
    }

    #[test]
    fn new_carries_the_chain_through_through() {
        let hop = ProxyConfig::new(ProxyScheme::Http {
            host: "hop".to_string(),
            port: 1080,
        });
        let chained = ProxyConfig::new(ProxyScheme::Socks5 {
            host: "final".to_string(),
            port: 1080,
            remote_dns: false,
        })
        .through(vec![hop]);
        assert_eq!(chained.hop_count(), 2);
        chained.validate().unwrap();
    }

    // -- MASQUE -------------------------------------------------------------

    /// Without the feature the capability is absent from the type, so the URL
    /// has to be refused where it is configured rather than where it is used.
    #[test]
    #[cfg(not(feature = "masque"))]
    fn parse_masque_without_the_feature_names_the_feature() {
        let err = ProxyConfig::parse("masque://proxy.example.com:443").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("--features masque"),
            "the error must name the feature to rebuild with: {message}"
        );
        assert!(
            ProxyConfig::parse_chain(["masque://hop:443", "socks5://final:1080"]).is_err(),
            "parse_chain goes through the same rejection"
        );
    }

    #[test]
    #[cfg(feature = "masque")]
    fn parse_masque_proxy() {
        let p = ProxyConfig::parse("masque://proxy.example.com:10001").unwrap();
        match &p.scheme {
            ProxyScheme::Masque { host, port } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(*port, 10001);
            }
            other => panic!("expected Masque, got {other:?}"),
        }
        assert!(p.auth.is_none());
        assert!(p.credential.is_none());
    }

    #[test]
    #[cfg(feature = "masque")]
    fn parse_masque_defaults_to_port_443() {
        let p = ProxyConfig::parse("masque://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Masque { port, .. } => assert_eq!(*port, 443),
            other => panic!("expected Masque, got {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "masque")]
    fn parse_masque_with_credentials() {
        let p = ProxyConfig::parse("masque://us%40er:p%23ss@proxy.example.com:443").unwrap();
        let auth = p.auth.as_ref().unwrap();
        assert_eq!(auth.username, "us@er");
        assert_eq!(auth.password, "p#ss");
        // Username/password over a header-based proxy is Basic in
        // Proxy-Authorization, which is what Bright Data's client sends.
        let (name, value) = p.http_auth_header().unwrap();
        assert_eq!(name, "Proxy-Authorization");
        assert_eq!(value, "Basic dXNAZXI6cCNzcw==");
    }

    #[test]
    #[cfg(feature = "masque")]
    fn masque_display_and_identity_round_trip_the_scheme() {
        let p = ProxyConfig::parse("masque://proxy.example.com:443").unwrap();
        assert_eq!(p.to_string(), "masque://proxy.example.com:443");
        assert!(p.identity().contains("masque"));
    }

    #[test]
    #[cfg(feature = "masque")]
    fn masque_cannot_be_a_chain_hop() {
        let err =
            ProxyConfig::parse_chain(["masque://hop:443", "socks5://final:1080"]).unwrap_err();
        assert!(
            err.to_string().contains("proxychain"),
            "unexpected error: {err}"
        );
        let err =
            ProxyConfig::parse_chain(["socks5://hop:1080", "masque://final:443"]).unwrap_err();
        assert!(
            err.to_string().contains("proxychain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn only_masque_forbids_the_direct_fallback() {
        // Only reachable with the feature: without it `masque://` does not
        // parse, so there is no such config to ask the question of.
        #[cfg(feature = "masque")]
        for url in [
            "masque://proxy.example.com:443",
            "masque://proxy.example.com",
        ] {
            assert!(
                ProxyConfig::parse(url).unwrap().forbids_direct_fallback(),
                "{url} must never fall back to a direct connection"
            );
        }
        // Every other scheme keeps honouring `proxy_fallback_direct`.
        for url in [
            "http://proxy.example.com:8080",
            "https://proxy.example.com:443",
            "socks5://proxy.example.com:1080",
            "socks5h://proxy.example.com:1080",
        ] {
            assert!(
                !ProxyConfig::parse(url).unwrap().forbids_direct_fallback(),
                "{url} must keep the existing fallback behaviour"
            );
        }
        // Chains of the fallback-eligible schemes stay eligible.
        assert!(
            !ProxyConfig::parse_chain(["http://a:1080", "socks5h://b:1080"])
                .unwrap()
                .forbids_direct_fallback()
        );
    }

    #[test]
    #[cfg(feature = "masque")]
    fn a_masque_hop_anywhere_forbids_the_direct_fallback() {
        // `validate` rejects MASQUE chains, so build one by hand: the guarantee
        // must not depend on validation having run first.
        let mut chained = ProxyConfig::new(ProxyScheme::Socks5 {
            host: "final".to_string(),
            port: 1080,
            remote_dns: true,
        });
        chained.chain = vec![ProxyConfig::new(ProxyScheme::Masque {
            host: "hop".to_string(),
            port: 443,
        })];
        assert!(chained.forbids_direct_fallback());
    }

    // -- ProxyCredential ----------------------------------------------------

    #[test]
    fn http_credential_on_socks5_is_a_configuration_error() {
        let err = ProxyConfig::parse("socks5://proxy.example.com:1080")
            .unwrap()
            .with_http_auth("Preshared", "s3cr3t")
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Preshared"), "unexpected error: {message}");
        assert!(message.contains("RFC 1929"), "unexpected error: {message}");

        // The same credential is fine on the header-based schemes.
        let header_based: &[&str] = &[
            "http://proxy.example.com:8080",
            "https://proxy.example.com:443",
            #[cfg(feature = "masque")]
            "masque://proxy:443",
        ];
        for url in header_based.iter().copied() {
            let proxy = ProxyConfig::parse(url)
                .unwrap()
                .with_http_auth("Preshared", "s3cr3t")
                .unwrap();
            assert_eq!(
                proxy.http_auth_header().unwrap(),
                ("Proxy-Authorization", "Preshared s3cr3t".to_string())
            );
        }
    }

    #[test]
    fn custom_credential_on_socks5_is_a_configuration_error() {
        let err = ProxyConfig::parse("socks5h://proxy.example.com:1080")
            .unwrap()
            .with_custom_auth(Arc::new(StaticAuthenticator {
                fragment: "tenant-a".into(),
                value: "PrivateToken token=abc".into(),
            }))
            .unwrap_err();
        assert!(
            err.to_string().contains("custom authenticator"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auth_and_credential_together_are_rejected() {
        let mut proxy = ProxyConfig::parse("http://user:pass@proxy:8080").unwrap();
        proxy.credential = Some(ProxyCredential::Http {
            scheme: "Bearer".into(),
            credentials: "t".into(),
        });
        let err = proxy.validate().unwrap_err();
        assert!(
            err.to_string().contains("exactly one"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auth_header_selection_switches_the_header_name() {
        let proxy = ProxyConfig::parse("https://proxy:443")
            .unwrap()
            .with_http_auth("PrivateToken", "token=abc")
            .unwrap()
            .with_auth_header(ProxyAuthHeader::Authorization);
        assert_eq!(
            proxy.http_auth_header().unwrap(),
            ("Authorization", "PrivateToken token=abc".to_string())
        );
    }

    #[test]
    fn legacy_user_pass_auth_still_drives_socks5_and_basic() {
        let socks = ProxyConfig::parse("socks5://user:pass@proxy:1080").unwrap();
        let user_pass = socks.socks5_user_pass().unwrap();
        assert_eq!(user_pass.username, "user");
        assert_eq!(user_pass.password, "pass");
        // Setting the same thing through the new enum is equivalent.
        let expected = "pass";
        let mut explicit = ProxyConfig::parse("socks5://proxy:1080").unwrap();
        explicit.credential = Some(ProxyCredential::UserPass {
            username: "user".into(),
            password: expected.into(),
        });
        explicit.validate().unwrap();
        assert_eq!(explicit.identity(), socks.identity());
        assert_eq!(explicit.socks5_user_pass().unwrap().password, expected);
    }

    #[test]
    fn credential_debug_redacts_secrets() {
        let http = ProxyCredential::Http {
            scheme: "Preshared".into(),
            credentials: "s3cr3t".into(),
        };
        let rendered = format!("{http:?}");
        assert!(rendered.contains("Preshared"));
        assert!(!rendered.contains("s3cr3t"), "{rendered}");

        let user_pass = ProxyCredential::UserPass {
            username: "user".into(),
            password: "<REDACTED>".into(),
        };
        assert!(!format!("{user_pass:?}").contains("fixture-pw"));
    }

    // -- identity() with the extended credentials ---------------------------

    #[derive(Debug)]
    struct StaticAuthenticator {
        fragment: String,
        value: String,
    }

    impl ProxyAuthenticator for StaticAuthenticator {
        fn identity_fragment(&self) -> String {
            self.fragment.clone()
        }
        fn authorization_value(&self) -> Option<String> {
            Some(self.value.clone())
        }
    }

    #[test]
    fn custom_credentials_keep_same_address_proxies_distinct() {
        let make = |fragment: &str, value: &str| {
            ProxyConfig::parse("https://proxy.example.com:443")
                .unwrap()
                .with_custom_auth(Arc::new(StaticAuthenticator {
                    fragment: fragment.into(),
                    value: value.into(),
                }))
                .unwrap()
        };
        let a = make("tenant-a", "PrivateToken token=aaa");
        let b = make("tenant-b", "PrivateToken token=bbb");

        assert_eq!(a.host_port(), b.host_port());
        assert_ne!(
            a.identity(),
            b.identity(),
            "same address + different credentials must not share a cooldown key"
        );
        assert_ne!(
            crate::protocol::RouteKey::from_proxy(Some(&a)),
            crate::protocol::RouteKey::from_proxy(Some(&b))
        );
        // The credential value itself never reaches the identity string.
        assert!(!a.identity().contains("aaa"), "{}", a.identity());
        // A proxy with no credentials is distinct from both.
        let anonymous = ProxyConfig::parse("https://proxy.example.com:443").unwrap();
        assert_ne!(anonymous.identity(), a.identity());
    }

    #[test]
    fn http_credentials_keep_same_address_proxies_distinct() {
        let make = |credentials: &str| {
            ProxyConfig::parse("https://proxy.example.com:443")
                .unwrap()
                .with_http_auth("Preshared", credentials)
                .unwrap()
        };
        let a = make("psk-a");
        let b = make("psk-b");
        assert_ne!(a.identity(), b.identity());
        assert!(!a.identity().contains("psk-a"), "{}", a.identity());
        // The scheme name is part of the key too.
        let bearer = ProxyConfig::parse("https://proxy.example.com:443")
            .unwrap()
            .with_http_auth("Bearer", "psk-a")
            .unwrap();
        assert_ne!(a.identity(), bearer.identity());
    }

    #[test]
    fn display_renders_chain_with_arrows() {
        let chain = ProxyConfig::parse_chain(["socks5://hop:1080", "http://final:8080"]).unwrap();
        assert_eq!(chain.to_string(), "socks5://hop:1080 -> http://final:8080");
    }
}
