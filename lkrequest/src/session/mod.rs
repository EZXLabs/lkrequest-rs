//! Session — a virtual browser user.
//!
//! A `Session` holds its own Cookie Jar, connection pool, and proxy config.
//! It represents a single "identity" — all requests from the same Session
//! share cookies and reuse connections.
//!
//! `Session` is `Clone + Send + Sync`.  Cloning is cheap (Arc reference count).
//! Multiple tasks can send requests through the same Session concurrently.

pub(crate) mod pipeline;
mod prefetch;
mod request;
mod streaming;
mod transport;

pub use prefetch::PrefetchResult;
pub use request::RequestBuilder;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use url::Url;

use crate::alt_svc::{AltSvcCache, BrokenQuicPolicy, BrokenQuicTracker};
use crate::client::Client;
use crate::connection_pool::ConnectionPool;
use crate::dns::HttpsRecord;
use crate::error::Error;
#[cfg(feature = "quic-h3")]
use crate::error::QuicPhase;
use crate::network_partition::{NetworkPartitionContext, PartitionedSessionStore};
use crate::protocol::{AcquisitionPolicy, FallbackPolicy, HttpIntent, ProtocolPolicy, RacePolicy};
use crate::proxy::ProxyConfig;
use crate::response::HttpVersion;
use crate::retry::RetryPolicy;

#[cfg(feature = "synthetic-fp")]
use lktls::session_store::InMemorySessionStore;
use lktls::session_store::SessionStore;

#[cfg(feature = "quic-h3")]
pub(crate) enum H3ConnectOutcome {
    Handshake(lkh3::H3Connection),
    ZeroRtt(lkh3::H3ZeroRttConnection),
}

#[cfg(feature = "quic-h3")]
impl H3ConnectOutcome {
    fn into_handshake(self) -> crate::error::Result<lkh3::H3Connection> {
        match self {
            Self::Handshake(connection) => Ok(connection),
            Self::ZeroRtt(_) => Err(Error::InvalidConfig(
                "internal error: unexpected HTTP/3 0-RTT connection".into(),
            )),
        }
    }
}

#[cfg(feature = "quic-h3")]
fn decode_extra_transport_parameters(
    parameters: &[(u64, String)],
) -> crate::error::Result<Vec<(quinn::VarInt, Vec<u8>)>> {
    parameters
        .iter()
        .map(|(id, value_hex)| {
            let id = quinn::VarInt::from_u64(*id).map_err(|_| {
                Error::InvalidConfig(format!(
                    "extra QUIC transport parameter id {id:#x} does not fit QUIC varint"
                ))
            })?;
            let value = decode_hex(value_hex)?;
            Ok((id, value))
        })
        .collect()
}

#[cfg(feature = "quic-h3")]
fn decode_transport_parameter_order(order: &[u64]) -> crate::error::Result<Vec<quinn::VarInt>> {
    order
        .iter()
        .map(|id| {
            quinn::VarInt::from_u64(*id).map_err(|_| {
                Error::InvalidConfig(format!(
                    "QUIC transport parameter order id {id:#x} does not fit QUIC varint"
                ))
            })
        })
        .collect()
}

/// Unbiased Fisher-Yates (Durstenfeld) shuffle of the QUIC transport-parameter
/// wire order, applied per connection. Chrome/BoringSSL randomizes the order of
/// its transport parameters on every connection (capture-verified), so a fixed
/// order is itself a fingerprint tell across connections.
#[cfg(feature = "quic-h3")]
fn shuffle_transport_parameter_order(order: &mut [quinn::VarInt]) {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let n = order.len();
    if n <= 1 {
        return;
    }
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    for i in (1..n).rev() {
        if rng.fill(&mut buf).is_err() {
            break;
        }
        let j = u32::from_le_bytes(buf) as usize % (i + 1);
        order.swap(i, j);
    }
}

/// Map 4 random bytes to a Chrome-style reserved GREASE transport-parameter id.
///
/// The returned id always satisfies the RFC 9000 §18.1 reserved form
/// `31*N + 27`, and is constrained so that it:
/// - is always encoded as an **8-byte** QUIC varint (value in `[2^30, 2^62)`),
///   matching the captured Chrome reserved id's on-wire width on every
///   connection — a sub-`2^30` id would encode shorter and shift the byte
///   layout, itself a fingerprint tell; and
/// - is **never** a transport parameter Quinn encodes locally (`0x00..=0x10`,
///   `0x20`, `0xb6`, `0x2ab2`, `0xff04de1a`), which `extra_transport_parameters`
///   rejects with `LocallyEncoded` (a connection-setup failure). All of those
///   are `< 2^30` except `0xff04de1a`, which is not of the `31*N + 27` form, so
///   none are reachable from this generator.
#[cfg(feature = "quic-h3")]
fn grease_reserved_tp_id(rand: u32) -> quinn::VarInt {
    // Smallest N whose id (= 31*N + 27) reaches the 8-byte-varint threshold 2^30.
    let n_min = ((1u64 << 30) - 27).div_ceil(31);
    let id = 27 + 31 * (n_min + rand as u64);
    // id ∈ [2^30, 2^30 + 31·2^32) ⊂ [2^30, 2^62) → always an 8-byte varint.
    quinn::VarInt::from_u64(id).expect("reserved GREASE id fits a QUIC varint")
}

/// Per-connection GREASE randomization of QUIC transport parameters, matching
/// Chrome/BoringSSL (capture-verified against Chrome 148):
/// - the reserved GREASE transport parameter (id `31*N + 27`, RFC 9000 §18.1)
///   gets a fresh random reserved id + random-length random value (the profile
///   stores a fixed placeholder; Chrome's is random per connection);
/// - `version_information` (0x11) gets a fresh random GREASE version
///   (`0x?a?a?a?a`, RFC 9000 §15.1) in its first available-version slot.
///
/// The `order` list's reference to the GREASE id is patched to the new id so the
/// (subsequently shuffled) wire order stays consistent.
#[cfg(feature = "quic-h3")]
fn randomize_quic_grease_params(
    extra: &mut [(quinn::VarInt, Vec<u8>)],
    order: &mut [quinn::VarInt],
) {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let fill = |b: &mut [u8]| {
        let _ = rng.fill(b);
    };

    for (id, value) in extra.iter_mut() {
        let id_v = id.into_inner();
        if id_v == 0x11 {
            // version_information = chosen(4) | available[GREASE(4), v1(4), …].
            // Randomize the GREASE version (first available slot, bytes 4..8).
            if value.len() >= 8 {
                let mut g = [0u8; 4];
                fill(&mut g);
                for b in g.iter_mut() {
                    *b = (*b & 0xf0) | 0x0a; // 0x?a?a?a?a reserved-version pattern
                }
                value[4..8].copy_from_slice(&g);
            }
        } else if id_v >= 27 && (id_v - 27) % 31 == 0 {
            // Reserved GREASE TP → fresh random reserved id and value. A
            // non-empty profile placeholder locks the captured wire length;
            // an empty placeholder retains the legacy randomized 1..=16 range.
            // `grease_reserved_tp_id` guarantees an 8-byte-varint, non-locally-
            // encoded id, so the encode below cannot be rejected.
            let mut n = [0u8; 4];
            fill(&mut n);
            let new_id = grease_reserved_tp_id(u32::from_le_bytes(n));
            let value_len = if value.is_empty() {
                let mut lb = [0u8; 1];
                fill(&mut lb);
                1 + (lb[0] as usize % 16)
            } else {
                value.len()
            };
            let mut val = vec![0u8; value_len];
            fill(&mut val);
            for slot in order.iter_mut() {
                if *slot == *id {
                    *slot = new_id;
                }
            }
            *id = new_id;
            *value = val;
        }
    }
}

#[cfg(feature = "quic-h3")]
fn build_initial_frame_layout_config(
    layout: &lkh3::InitialFrameLayoutProfile,
) -> quinn::InitialFrameLayoutConfig {
    quinn::InitialFrameLayoutConfig {
        target_udp_payload_size: layout.target_udp_payload_size,
        packets: layout
            .packets
            .iter()
            .map(|packet| quinn::InitialPacketLayoutConfig {
                packet_number: packet.packet_number,
                frames: packet
                    .frames
                    .iter()
                    .map(|element| match *element {
                        lkh3::InitialFrameElement::Crypto { offset, length } => {
                            quinn::InitialFrameElementConfig::Crypto { offset, length }
                        }
                        lkh3::InitialFrameElement::Padding { length } => {
                            quinn::InitialFrameElementConfig::Padding { length }
                        }
                        lkh3::InitialFrameElement::Ping => quinn::InitialFrameElementConfig::Ping,
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(feature = "quic-h3")]
fn decode_hex(value: &str) -> crate::error::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::InvalidConfig(
            "extra QUIC transport parameter value must be even-length hex".into(),
        ));
    }

    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

#[cfg(feature = "quic-h3")]
fn hex_nibble(byte: u8) -> crate::error::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidConfig(
            "extra QUIC transport parameter value must be hex".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// RedirectPolicy
// ---------------------------------------------------------------------------

/// Controls how HTTP redirects (3xx) are handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Do not follow redirects; return the 3xx response as-is.
    None,
    /// Follow redirects up to the specified number of hops.
    ///
    /// Exceeding the limit returns [`Error::TooManyRedirects`].
    /// The default is `Follow(10)`.
    Follow(u32),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Follow(10)
    }
}

impl RedirectPolicy {
    /// Returns the maximum number of redirects to follow, or `None` if
    /// redirects are disabled.
    pub(crate) fn max_redirects(&self) -> Option<u32> {
        match self {
            Self::None => Option::None,
            Self::Follow(n) => Some(*n),
        }
    }
}

// ---------------------------------------------------------------------------
// Idempotency (per-request 0-RTT opt-in, Chrome model)
// ---------------------------------------------------------------------------

/// Whether a request is **safe to replay** — governing both QUIC 0-RTT / TLS
/// early data and automatic retries after a transport failure.
///
/// Mirrors the tri-state `HttpRequestInfo::idempotency` flag in Chromium
/// (`net/base/idempotency.h`) so that replay decisions follow the same rules
/// as Chrome.
///
/// ## Semantics
///
/// The same predicate ([`can_send_early_data`]) decides two things:
///
/// | Value | Safe to replay (0-RTT *and* auto-retry)? |
/// |-------|------------------------------------------|
/// | [`Idempotency::Default`] | only for RFC 9110 §9.2.1 *safe* methods: `GET`, `HEAD`, `OPTIONS`, `TRACE` |
/// | [`Idempotency::Idempotent`] | yes — caller asserts the request is safe to replay (e.g. POST with an Idempotency-Key header) |
/// | [`Idempotency::NotIdempotent`] | no — caller explicitly opts out even for safe methods |
///
/// The defaults align with Chrome's `HttpNetworkTransaction::Start()` and
/// RFC 8470 §4 ("clients MAY send requests with safe HTTP methods ... in
/// early data when it is available and MUST NOT send unsafe methods ... in
/// early data"). Methods whose safety is not known (custom extension
/// methods) fall through the [`Idempotency::Default`] arm as "not safe",
/// matching the "MUST NOT" clause.
///
/// ## Where it applies
///
/// - **QUIC 0-RTT** — lkrequest attempts early data only when a resumable H3
///   session exists and this predicate says the request is replay-safe. If the
///   server rejects early data, the speculative H3 request is dropped and
///   replayed after the normal handshake.
/// - **Automatic retries** — a configured [`RetryPolicy`](crate::retry::RetryPolicy)
///   re-sends the (buffered) request body. For non-idempotent methods, a retry
///   only happens when the failure *proves* the request was never processed
///   (see [`Error::is_safe_to_replay`](crate::error::Error::is_safe_to_replay))
///   *or* this is set to [`Idempotency::Idempotent`]. A timeout/reset after a
///   `POST` was transmitted is **not** silently retried. See
///   [`crate::retry::retry_is_replay_safe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Idempotency {
    /// Decide automatically based on the HTTP method (RFC 9110 safe methods).
    #[default]
    Default,
    /// Caller asserts the request is safe to replay. Allows 0-RTT for any
    /// method, including POST/PUT/DELETE.
    Idempotent,
    /// Caller declares the request is unsafe to replay. Disables 0-RTT
    /// even for methods that would otherwise be considered safe.
    NotIdempotent,
}

/// Decide whether a request may be sent in QUIC 0-RTT / TLS early data.
///
/// See [`Idempotency`] for the rules. This is the public form of Chrome's
/// `HttpNetworkTransaction::Start()` logic:
///
/// ```text
/// can_send_early_data = idempotency == IDEMPOTENT
///   || (idempotency == DEFAULT && HttpUtil::IsMethodSafe(method))
/// ```
pub fn can_send_early_data(method: &http::Method, idempotency: Idempotency) -> bool {
    match idempotency {
        Idempotency::Idempotent => true,
        Idempotency::NotIdempotent => false,
        Idempotency::Default => matches!(
            *method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
        ),
    }
}

// ---------------------------------------------------------------------------
// AcceptEncoding bitflags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Flags controlling which content encodings to advertise in `Accept-Encoding`
    /// and which decompression algorithms to apply on the response.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// // Only advertise gzip
    /// let resp = session.get("https://example.com")
    ///     .accept_encoding(AcceptEncoding::GZIP)
    ///     .send().await?;
    ///
    /// // Advertise br + gzip (common for modern browsers)
    /// let resp = session.get("https://example.com")
    ///     .accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
    ///     .send().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AcceptEncoding: u8 {
        /// gzip encoding.
        const GZIP    = 0b0001;
        /// Brotli (br) encoding.
        const BR      = 0b0010;
        /// deflate encoding.
        const DEFLATE = 0b0100;
        /// Zstandard (zstd) encoding.
        const ZSTD    = 0b1000;
        /// All supported encodings (gzip + br + deflate + zstd).
        const ALL     = 0b1111;
    }
}

impl AcceptEncoding {
    /// Chrome default: `gzip, deflate, br, zstd`
    pub const CHROME_DEFAULT: Self = Self::ALL;

    /// Firefox default: `gzip, deflate, br, zstd`
    pub const FIREFOX_DEFAULT: Self = Self::ALL;

    /// Safari default: `gzip, deflate, br`
    pub const SAFARI_DEFAULT: Self = Self::GZIP.union(Self::DEFLATE).union(Self::BR);

    /// Convert to an `Accept-Encoding` header value string.
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if self.contains(Self::GZIP) {
            parts.push("gzip");
        }
        if self.contains(Self::DEFLATE) {
            parts.push("deflate");
        }
        if self.contains(Self::BR) {
            parts.push("br");
        }
        if self.contains(Self::ZSTD) {
            parts.push("zstd");
        }
        parts.join(", ")
    }
}

/// Global monotonic request ID counter.
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_request_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub use cookie_store::CookieStore;

/// The two cookie name prefixes defined by RFC 6265bis §4.1.3.
const SECURE_COOKIE_PREFIX: &str = "__Secure-";
const HOST_COOKIE_PREFIX: &str = "__Host-";

/// ASCII case-insensitive prefix test.  Both prefixes are pure ASCII, and
/// browsers match them case-insensitively.
fn starts_with_ascii_ci(name: &str, prefix: &str) -> bool {
    let (name, prefix) = (name.as_bytes(), prefix.as_bytes());
    name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Was this `Set-Cookie` delivered over what RFC 6265bis calls a *secure
/// channel*?
///
/// "Secure channel" here means an `https`/`wss` URL.  Browsers additionally
/// treat `http://localhost` as a trustworthy origin; we deliberately do not,
/// because this client targets remote origins — the stricter rule can never
/// admit a cookie a real browser would have refused.
fn is_secure_channel(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "wss")
}

/// Decide whether a `Set-Cookie` received from an **origin server** may enter
/// the jar.
///
/// Returns `true` when the cookie may be stored, and `false` when a conforming
/// user agent must **ignore the cookie entirely**.  Two RFC 6265bis rules are
/// enforced here; both reduce to the same question — *was this set over a
/// secure channel?* — which is why they share one code path and one set of
/// call sites:
///
/// * §5.6 (storage model, step 15) — a cookie whose `secure-only-flag` is set
///   but which did not arrive over a secure channel is ignored, **whatever its
///   name**.  `cookie_store` 0.22 does not implement this, so it happens here.
/// * §4.1.3 cookie name prefixes:
///   * `__Secure-` (§4.1.3.1) — the cookie must carry the `Secure` attribute
///     and must have been set over a secure channel.
///   * `__Host-` (§4.1.3.2) — everything `__Secure-` requires, and in addition
///     it must **not** carry a `Domain` attribute, and its `Path` must be
///     exactly `/`.
///   * Any other name is unaffected by the prefix rules.
///
/// Prefix matching is ASCII case-insensitive, matching browser behaviour.
///
/// This is the origin-server path only.  The programmatic APIs
/// ([`Session::set_cookie`], [`Session::set_cookie_with_attrs`] and
/// [`Session::remove_cookie`]) deliberately bypass it: they seed or clear jar
/// state rather than consuming a header, and a removal must never be blocked.
fn origin_cookie_allows_storage(cookie: &cookie_store::RawCookie<'_>, url: &Url) -> bool {
    let secure_attr = cookie.secure().unwrap_or(false);
    let secure_channel = is_secure_channel(url);

    // §5.6 step 15: `Secure` set over a non-secure channel is ignored outright,
    // regardless of the cookie's name.
    if secure_attr && !secure_channel {
        return false;
    }

    let name = cookie.name();
    let host_prefixed = starts_with_ascii_ci(name, HOST_COOKIE_PREFIX);
    let secure_prefixed = starts_with_ascii_ci(name, SECURE_COOKIE_PREFIX);
    if !host_prefixed && !secure_prefixed {
        return true;
    }

    // §4.1.3: both prefixes require `Secure` *plus* a secure channel.  The
    // check above already rejected `Secure`-over-`http`, so what is left to
    // catch here is a prefixed cookie that omits `Secure` altogether, and a
    // prefixed non-`Secure` cookie offered over an insecure channel.
    if !secure_attr || !secure_channel {
        return false;
    }

    // `__Host-` additionally locks the cookie to the exact host and to "/".
    if host_prefixed {
        return cookie.domain().is_none() && cookie.path() == Some("/");
    }
    true
}

// ---------------------------------------------------------------------------
// DNS HTTPS (SVCB) record hand-off
// ---------------------------------------------------------------------------

/// What a caller already knows about the target's DNS HTTPS (SVCB) record.
///
/// Passed to [`Session::build_tls_connector`] so the TLS handshake reuses the
/// record protocol discovery already fetched for this request instead of
/// issuing a second, possibly divergent, HTTPS-RR query.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum DiscoveredHttpsRr<'a> {
    /// Nobody has queried yet — the connector may run its own (gated) lookup.
    #[default]
    Unqueried,
    /// A caller already ran the query: `Some` is the record it returned, `None`
    /// means the query came back empty. Either way, do **not** query again.
    Queried(Option<&'a HttpsRecord>),
}

/// How long a parked HTTPS-RR stays claimable.
///
/// The hand-off is published by `pipeline::discover_quic_support` and claimed at
/// the top of [`Session::establish_connection`], microseconds later on the same
/// request. The window only has to survive that gap; it is deliberately far too
/// short to act as a DNS cache.
const HTTPS_RR_HANDOFF_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on parked entries, so a session that discovers many origins
/// without ever reaching a TLS handshake (e.g. an all-H3 workload) cannot grow
/// the map without limit.
const HTTPS_RR_HANDOFF_MAX_ENTRIES: usize = 32;

/// A DNS HTTPS (SVCB) record that protocol discovery fetched for an in-flight
/// request, parked for the TLS handshake of that same request.
///
/// `establish_connection` is shared by the buffered, streaming, preconnect and
/// WebSocket paths and does not receive the `QuicDiscovery` value, so discovery
/// parks the record here and the connector claims it. Entries are **single-use**
/// (claiming removes them) and expire after [`HTTPS_RR_HANDOFF_TTL`]: this is a
/// hand-off slot, not a resolver cache.
#[derive(Default)]
pub(crate) struct HttpsRrHandoff {
    entries: std::collections::HashMap<String, HttpsRrHandoffEntry>,
}

struct HttpsRrHandoffEntry {
    published_at: std::time::Instant,
    /// The lookup result — `None` means "queried, no record", which is just as
    /// worth handing off as a hit: it spares the second query too.
    record: Option<HttpsRecord>,
}

impl HttpsRrHandoff {
    fn publish(&mut self, host: &str, record: Option<HttpsRecord>, now: std::time::Instant) {
        self.entries
            .retain(|_, entry| now.duration_since(entry.published_at) < HTTPS_RR_HANDOFF_TTL);
        if self.entries.len() >= HTTPS_RR_HANDOFF_MAX_ENTRIES && !self.entries.contains_key(host) {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.published_at)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            host.to_string(),
            HttpsRrHandoffEntry {
                published_at: now,
                record,
            },
        );
    }

    fn claim(&mut self, host: &str, now: std::time::Instant) -> Option<Option<HttpsRecord>> {
        let entry = self.entries.remove(host)?;
        if now.duration_since(entry.published_at) >= HTTPS_RR_HANDOFF_TTL {
            return None;
        }
        Some(entry.record)
    }

    /// Like [`claim`](Self::claim), but leaves the entry in place for the
    /// caller that consumes it (see [`Session::peek_discovered_https_rr`]).
    #[cfg(feature = "quic-h3")]
    fn peek(&self, host: &str, now: std::time::Instant) -> Option<Option<HttpsRecord>> {
        let entry = self.entries.get(host)?;
        if now.duration_since(entry.published_at) >= HTTPS_RR_HANDOFF_TTL {
            return None;
        }
        Some(entry.record.clone())
    }
}

/// A session representing a single virtual browser user.
///
/// # Example
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// let session = client.session().build();
///
/// // Concurrent requests share the session's cookie jar and connections.
/// let resp = session.get("https://example.com").send().await?;
/// println!("Status: {}", resp.status());
/// println!("Body: {}", resp.text()?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: Arc<SessionInner>,
}

/// Inner state of a Session, shared across clones.
#[allow(dead_code)]
pub(crate) struct SessionInner {
    /// The client this session was created from (fingerprint config).
    pub client: Client,

    /// Cookie jar — per-session, lock-free reads via ArcSwap.
    ///
    /// Reads (every request, to inject Cookie header) are lock-free via `load()`.
    /// Writes (Set-Cookie responses) use `rcu()` for safe copy-on-write.
    pub cookie_jar: ArcSwap<CookieStore>,

    /// Connection pool — per-session, protected by Mutex (short critical sections).
    pub pool: Mutex<ConnectionPool>,

    /// Proxy configuration for this session (immutable after creation).
    pub proxy: Option<ProxyConfig>,

    /// Redirect policy for this session.
    pub redirect_policy: RedirectPolicy,

    /// When `true`, refuse to follow a redirect to a non-HTTPS URL. Default
    /// `false` (Chrome-faithful: scheme downgrades are followed).
    pub https_only: bool,

    /// HSTS / scheme-upgrade policy: decides whether an `http://` URL is
    /// upgraded to `https://` before connecting. Default [`NoHsts`](crate::hsts::NoHsts).
    pub hsts_policy: Arc<dyn crate::hsts::HstsPolicy>,

    /// TLS session ticket store for session resumption (shared across connections).
    pub session_store: Arc<dyn SessionStore>,

    /// Optional retry policy for failed requests.
    pub retry_policy: Option<Arc<dyn RetryPolicy>>,

    /// Per-session ECHConfigList override (raw DER bytes).
    /// Takes precedence over the client's `ech_config`.
    pub ech_config: Option<Vec<u8>>,

    /// Session-level middleware stack (applied after client middlewares).
    pub middlewares: crate::middleware::MiddlewareStack,

    /// Effective runtime protocol behavior for this session.
    pub protocol_policy: ProtocolPolicy,

    /// Preferred HTTP version for this session.
    pub preferred_http_version: PreferredHttpVersion,

    /// How `Auto` mode chooses between TCP and QUIC when both are viable.
    pub protocol_selection_policy: ProtocolSelectionPolicy,

    /// Tunables for the Chrome-like TCP/QUIC racing policy.
    pub chrome_like_protocol_config: ChromeLikeProtocolConfig,

    /// Default Accept-Encoding for requests in this session.
    pub default_accept_encoding: Option<AcceptEncoding>,

    /// Session-level header sending order template.
    pub header_order: Option<Vec<http::header::HeaderName>>,

    /// Session-level HTTP/3-specific header sending order template.
    pub h3_header_order: Option<Vec<http::header::HeaderName>>,

    /// Session-level cookie sending order template.
    pub cookie_order: Option<Vec<Box<str>>>,

    /// Cached Alt-Svc advertisements observed from responses.
    pub alt_svc_cache: AltSvcCache,

    /// Cooldown tracker for origins whose QUIC path is currently considered broken.
    pub broken_quic_tracker: BrokenQuicTracker,

    /// DNS HTTPS (SVCB) records fetched by protocol discovery, parked for the
    /// TLS handshake of the same request. See [`HttpsRrHandoff`].
    pub https_rr_handoff: Mutex<HttpsRrHandoff>,

    /// QUIC handshakes currently in-flight, keyed by connection key.
    ///
    /// When two concurrent requests target the same origin and neither has
    /// a pooled H3 connection yet, we want only one of them to run the
    /// handshake; the other should wait and then reuse the pooled sender
    /// instead of racing a second full QUIC handshake (and getting its
    /// connection silently dropped when the pool inserts the first one's
    /// sender over it). Each entry is an [`Arc<tokio::sync::Notify>`] that
    /// the handshaking task will `notify_waiters()` on completion.
    #[cfg(feature = "quic-h3")]
    pub quic_in_flight: Mutex<
        std::collections::HashMap<crate::connection_pool::ConnectionKey, Arc<tokio::sync::Notify>>,
    >,
}

impl Session {
    /// Returns a reference to the underlying client.
    pub fn client(&self) -> &Client {
        &self.inner.client
    }

    /// Returns the session-level header order, if set.
    pub fn header_order(&self) -> Option<&[http::header::HeaderName]> {
        self.inner.header_order.as_deref()
    }

    /// Returns the session-level HTTP/3-specific header order, if set.
    pub fn h3_header_order(&self) -> Option<&[http::header::HeaderName]> {
        self.inner.h3_header_order.as_deref()
    }

    /// Returns the session-level cookie order, if set.
    pub fn cookie_order(&self) -> Option<&[Box<str>]> {
        self.inner.cookie_order.as_deref()
    }

    pub(crate) fn alt_svc_cache(&self) -> &AltSvcCache {
        &self.inner.alt_svc_cache
    }

    pub(crate) fn broken_quic_tracker(&self) -> &BrokenQuicTracker {
        &self.inner.broken_quic_tracker
    }

    pub fn protocol_policy(&self) -> &ProtocolPolicy {
        &self.inner.protocol_policy
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn chrome_like_protocol_config(&self) -> ChromeLikeProtocolConfig {
        self.inner.chrome_like_protocol_config
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn spawn_background_quic_probe(
        &self,
        host: String,
        port: u16,
        conn_key: crate::connection_pool::ConnectionKey,
        discovery: crate::session::pipeline::QuicDiscovery,
        proxy: Option<crate::proxy::ProxyConfig>,
    ) {
        let session = self.clone();
        tokio::spawn(async move {
            let permit = match session.reserve_connection() {
                Ok(permit) => permit,
                Err(error) => {
                    tracing::debug!(host = %host, port, error = %error, "quic.background_probe_skipped");
                    return;
                }
            };
            match session
                .establish_h3_connection(
                    &host,
                    port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy.as_ref(),
                )
                .await
            {
                Ok(h3_conn) => {
                    session
                        .broken_quic_tracker()
                        .mark_working_for_route(&discovery.route, &discovery.origin);
                    session
                        .broken_quic_tracker()
                        .mark_route_working(&discovery.route);
                    session
                        .alt_svc_cache()
                        .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
                    let (sender, driver) = h3_conn.into_parts();
                    let mut pool = session.inner.pool.lock();
                    pool.insert_h3_reserved(conn_key, sender, driver, permit);
                    tracing::debug!(host = %host, port, "quic.background_probe_succeeded");
                }
                Err(error) => {
                    if error.is_quic_handshake_failure() {
                        session
                            .broken_quic_tracker()
                            .mark_broken_for_route(&discovery.route, &discovery.origin);
                        session
                            .alt_svc_cache()
                            .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    }
                    tracing::debug!(
                        host = %host,
                        port,
                        error = %error,
                        "quic.background_probe_failed"
                    );
                }
            }
        });
    }

    #[cfg(not(feature = "quic-h3"))]
    pub(crate) fn spawn_background_quic_probe(
        &self,
        _host: String,
        _port: u16,
        _conn_key: crate::connection_pool::ConnectionKey,
        _discovery: crate::session::pipeline::QuicDiscovery,
        _proxy: Option<crate::proxy::ProxyConfig>,
    ) {
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn spawn_background_tcp_probe(
        &self,
        host: String,
        port: u16,
        scheme: crate::connection_pool::Scheme,
        conn_key: crate::connection_pool::ConnectionKey,
        proxy: Option<crate::proxy::ProxyConfig>,
        preferred_http_version: PreferredHttpVersion,
    ) {
        let session = self.clone();
        tokio::spawn(async move {
            if let Err(error) = session
                .preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    proxy,
                    preferred_http_version,
                )
                .await
            {
                tracing::debug!(
                    host = %host,
                    port,
                    error = %error,
                    "tcp.background_probe_failed"
                );
            } else {
                tracing::debug!(host = %host, port, "tcp.background_probe_succeeded");
            }
        });
    }

    // -------------------------------------------------------------------
    // Cookie management (session-level)
    // -------------------------------------------------------------------

    /// Set a cookie in the session's cookie jar.
    ///
    /// The cookie is associated with `url` and will be sent on subsequent
    /// requests to matching domains/paths according to standard cookie rules.
    ///
    /// The RFC 6265bis §4.1.3 `__Secure-` / `__Host-` name prefixes are **not**
    /// enforced here — this seeds the jar from application state rather than
    /// from an origin server.  Use [`Session::set_cookie_raw`] if you want the
    /// browser rules applied.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.set_cookie("https://example.com", "session_id", "abc123");
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cookie(&self, url: &str, name: &str, value: &str) {
        match Url::parse(url) {
            Ok(parsed) => {
                // Deliberately NOT gated on the RFC 6265bis §4.1.3 name prefixes.
                // That rule governs cookies a user agent *receives* from an
                // origin server; this is the application seeding its own jar
                // (e.g. replaying a cookie a real browser already earned), which
                // is the local-trust equivalent of importing a browser cookie
                // store.  This API cannot express `Secure`, so gating it would
                // silently drop every `__Secure-`/`__Host-` cookie handed to it.
                // Use `set_cookie_raw` if you want the browser rules applied.
                let raw = cookie_store::RawCookie::new(name.to_string(), value.to_string());
                self.inner.cookie_jar.rcu(move |old| {
                    let mut jar = (**old).clone();
                    let _ = jar.insert_raw(&raw, &parsed);
                    jar
                });
            }
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie: invalid URL, cookie not set");
            }
        }
    }

    /// Set a cookie with full attributes (path, domain, etc.).
    ///
    /// This allows setting cookies that are scoped to specific paths, which
    /// enables multiple cookies with the **same name** but different paths —
    /// a common pattern with real browsers.
    ///
    /// As with [`Session::set_cookie`], the RFC 6265bis §4.1.3 `__Secure-` /
    /// `__Host-` name prefixes are **not** enforced for caller-supplied cookies.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // Same name, different paths — both will be sent for /api/users
    /// session.set_cookie_with_attrs(
    ///     "https://example.com",
    ///     "token", "root_val",
    ///     Some("/"), None, false, false,
    /// );
    /// session.set_cookie_with_attrs(
    ///     "https://example.com",
    ///     "token", "api_val",
    ///     Some("/api"), None, false, false,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn set_cookie_with_attrs(
        &self,
        url: &str,
        name: &str,
        value: &str,
        path: Option<&str>,
        domain: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie_with_attrs: invalid URL, cookie not set");
                return;
            }
        };
        let mut builder = cookie_store::RawCookie::build(cookie_store::RawCookie::new(
            name.to_string(),
            value.to_string(),
        ));
        if let Some(p) = path {
            builder = builder.path(p);
        }
        if let Some(d) = domain {
            builder = builder.domain(d);
        }
        if secure {
            builder = builder.secure(true);
        }
        if http_only {
            builder = builder.http_only(true);
        }
        let built = builder.build();
        // Deliberately NOT gated on the RFC 6265bis §4.1.3 name prefixes — same
        // reasoning as `set_cookie`: this is caller-supplied jar state, not a
        // server-sent `Set-Cookie`.  Imported jars (Netscape `cookies.txt`,
        // browser exports) routinely carry a `domain` column even for host-only
        // cookies, so gating here would silently drop valid `__Host-` cookies
        // during a replay.
        self.inner.cookie_jar.rcu(move |old| {
            let mut jar = (**old).clone();
            let _ = jar.insert_raw(&built, &parsed);
            jar
        });
    }

    /// Set a cookie from a raw `Set-Cookie` header string.
    ///
    /// This is the most flexible way to set cookies, supporting all cookie
    /// attributes (path, domain, expires, max-age, secure, httponly, samesite).
    ///
    /// Because it takes verbatim `Set-Cookie` syntax it is treated as an
    /// origin-server cookie, so the RFC 6265bis storage rules **are** enforced
    /// and a violating cookie is ignored exactly as a browser would ignore it:
    ///
    /// * §5.6 step 15 — any cookie carrying `Secure` whose URL is not `https`
    ///   / `wss`.
    /// * §4.1.3 — a `__Secure-` cookie without `Secure` (or not set over
    ///   `https`), or a `__Host-` cookie carrying a `Domain` attribute or a
    ///   `Path` other than `/`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.set_cookie_raw(
    ///     "https://example.com",
    ///     "id=abc; Path=/; Domain=example.com; Secure; HttpOnly",
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cookie_raw(&self, url: &str, set_cookie_header: &str) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie_raw: invalid URL, cookie not set");
                return;
            }
        };
        match cookie_store::RawCookie::parse(set_cookie_header.to_string()) {
            Ok(raw) => {
                // This API takes verbatim `Set-Cookie` header syntax, so it is
                // the origin-server path: the RFC 6265bis storage rules apply
                // and a browser would ignore a cookie that violates them.
                if !origin_cookie_allows_storage(&raw, &parsed) {
                    tracing::debug!(
                        url = %parsed,
                        cookie = %raw.name(),
                        "session.set_cookie_raw: cookie rejected by the RFC 6265bis storage rules"
                    );
                    return;
                }
                self.inner.cookie_jar.rcu(move |old| {
                    let mut jar = (**old).clone();
                    let _ = jar.insert_raw(&raw, &parsed);
                    jar
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "session.set_cookie_raw: failed to parse Set-Cookie header");
            }
        }
    }

    /// Get all cookies that would be sent for the given URL.
    ///
    /// Returns a list of `(name, value)` pairs matching the URL's domain and
    /// path.  **May contain duplicate names** if the same cookie name exists
    /// at different paths/domains.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let cookies = session.get_cookies("https://example.com/api/users");
    /// // Could contain: [("token", "api_val"), ("token", "root_val"), ("session", "xyz")]
    /// for (name, value) in &cookies {
    ///     println!("{name}={value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookies(&self, url: &str) -> Vec<(String, String)> {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let jar = self.inner.cookie_jar.load();
        jar.matches(&parsed)
            .into_iter()
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect()
    }

    /// Get the value of a specific cookie by name for the given URL.
    ///
    /// If multiple cookies with the same name match (different paths),
    /// returns the most specific one (longest path match, per RFC 6265).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// if let Some(value) = session.get_cookie("https://example.com/api", "token") {
    ///     println!("token = {value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookie(&self, url: &str, name: &str) -> Option<String> {
        let parsed = Url::parse(url).ok()?;
        let jar = self.inner.cookie_jar.load();
        // CookieStore::matches returns cookies sorted by path specificity
        // (most specific first, per RFC 6265 Section 5.4)
        jar.matches(&parsed)
            .into_iter()
            .find(|c| c.name() == name)
            .map(|c| c.value().to_string())
    }

    /// Get all values for a specific cookie name matching the given URL.
    ///
    /// Returns multiple values when the same cookie name exists at different
    /// paths or domains.  Values are ordered by path specificity (most
    /// specific first).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // If "token" exists at "/" and "/api":
    /// let values = session.get_cookie_values("https://example.com/api", "token");
    /// // Returns: ["api_val", "root_val"]
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookie_values(&self, url: &str, name: &str) -> Vec<String> {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let jar = self.inner.cookie_jar.load();
        jar.matches(&parsed)
            .into_iter()
            .filter(|c| c.name() == name)
            .map(|c| c.value().to_string())
            .collect()
    }

    /// Remove all cookies matching the given name for the specified URL's domain.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.remove_cookie("https://example.com", "session_id");
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_cookie(&self, url: &str, name: &str) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.remove_cookie: invalid URL, cookie not removed");
                return;
            }
        };
        let name = name.to_string();
        self.inner.cookie_jar.rcu(move |old| {
            let mut jar = (**old).clone();
            // Deliberately NOT gated on the RFC 6265bis §4.1.3 name prefixes.
            // This synthesises an already-expired cookie purely to evict an
            // existing entry; it carries no `Secure` attribute, so gating it
            // would make `__Secure-`/`__Host-` cookies permanently unremovable.
            // A removal must never be blocked by the prefix rules.
            let removal =
                cookie_store::RawCookie::build(cookie_store::RawCookie::new(name.clone(), ""))
                    .max_age(cookie::time::Duration::ZERO)
                    .path("/")
                    .build();
            let _ = jar.insert_raw(&removal, &parsed);
            jar
        });
    }

    /// Remove all cookies from the session's cookie jar.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.clear_cookies();
    /// assert!(session.get_cookies("https://example.com").is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear_cookies(&self) {
        self.inner.cookie_jar.store(Arc::new(CookieStore::new()));
    }

    /// Get the cookie header string that would be sent for the given URL.
    ///
    /// Returns `None` if no cookies match.  May contain duplicate names
    /// (from different paths/domains).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// if let Some(header) = session.cookie_header("https://example.com") {
    ///     println!("Cookie: {header}");  // "session_id=abc123; theme=dark"
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie_header(&self, url: &str) -> Option<String> {
        let parsed = Url::parse(url).ok()?;
        let jar = self.inner.cookie_jar.load();
        let cookies: Vec<String> = jar
            .matches(&parsed)
            .into_iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect();
        if cookies.is_empty() {
            None
        } else {
            Some(cookies.join("; "))
        }
    }

    // -------------------------------------------------------------------
    // Connection pool monitoring
    // -------------------------------------------------------------------

    /// Return a snapshot of the connection pool statistics.
    pub fn pool_stats(&self) -> crate::connection_pool::PoolStats {
        self.inner.pool.lock().stats()
    }

    pub(crate) fn reserve_connection(
        &self,
    ) -> crate::error::Result<crate::connection_pool::ConnectionPermit> {
        let mut pool = self.inner.pool.lock();
        pool.try_reserve_connection().ok_or_else(|| {
            crate::error::Error::Pool(format!(
                "session connection limit reached ({} connections)",
                pool.max_total,
            ))
        })
    }

    pub(crate) fn connection_budget(&self) -> crate::connection_pool::ConnectionBudget {
        self.inner.pool.lock().connection_budget()
    }

    /// Remove all connections from the pool, aborting their driver tasks.
    ///
    /// Subsequent requests will establish fresh connections.  This is
    /// primarily useful for benchmarks that need to measure cold-start
    /// latency without leaking spawned tasks and TIME_WAIT sockets.
    pub fn pool_clear(&self) {
        self.inner.pool.lock().clear();
    }

    // -------------------------------------------------------------------
    // DNS HTTPS (SVCB) record hand-off
    // -------------------------------------------------------------------

    /// Park the HTTPS-RR lookup result for `host` so the TLS handshake of this
    /// request can reuse it instead of querying again.
    ///
    /// Only ever called from the local-DNS branch of
    /// `pipeline::discover_quic_support` — nothing is parked on remote-DNS
    /// routes, because nothing is looked up there.
    pub(crate) fn publish_discovered_https_rr(&self, host: &str, record: Option<HttpsRecord>) {
        self.inner
            .https_rr_handoff
            .lock()
            .publish(host, record, std::time::Instant::now());
    }

    /// Claim the HTTPS RR parked for `host` by protocol discovery.
    ///
    /// Returns `None` when nothing fresh is parked (so the caller must do its
    /// own lookup), `Some(None)` when discovery queried and found no record,
    /// and `Some(Some(record))` for a hit. The entry is consumed.
    pub(crate) fn take_discovered_https_rr(&self, host: &str) -> Option<Option<HttpsRecord>> {
        self.inner
            .https_rr_handoff
            .lock()
            .claim(host, std::time::Instant::now())
    }

    /// Read the HTTPS RR parked for `host` **without** consuming it.
    ///
    /// The H3 handshake reads the hand-off this way because it is not the last
    /// user of the record on its request: when the QUIC attempt fails, the same
    /// request falls back to TCP and `establish_connection` still has to find
    /// the record there. Consuming it here would leave that fallback to issue a
    /// second query for the host this request already resolved.
    ///
    /// Freshness is unchanged — an entry past [`HTTPS_RR_HANDOFF_TTL`] is not
    /// returned, and it is still the *claim* that removes it.
    #[cfg(feature = "quic-h3")]
    pub(crate) fn peek_discovered_https_rr(&self, host: &str) -> Option<Option<HttpsRecord>> {
        self.inner
            .https_rr_handoff
            .lock()
            .peek(host, std::time::Instant::now())
    }

    // -------------------------------------------------------------------
    // TLS connector construction
    // -------------------------------------------------------------------

    /// Build a fully configured [`crate::tls::TlsConnector`] from Client + Session settings.
    ///
    /// Applies verify, custom CA, keylog, and ECH (session > client > DNS auto)
    /// configurations. Each call site only needs to provide the TLS profile
    /// and ALPS payload (which vary depending on protocol context).
    ///
    /// `dns_https` carries an HTTPS RR the caller already fetched for this
    /// request. Only when it is [`DiscoveredHttpsRr::Unqueried`] does this
    /// method run its own lookup — otherwise every HTTPS request would pay a
    /// second HTTPS-RR round trip, and the ECH config used could disagree with
    /// the record the H3 decision was based on.
    pub(crate) async fn build_tls_connector(
        &self,
        tls_profile: lktls::profile::types::TlsProfile,
        alps_payload: Option<Vec<u8>>,
        host: &str,
        is_remote_dns: bool,
        dns_https: DiscoveredHttpsRr<'_>,
    ) -> crate::tls::TlsConnector {
        let client = &self.inner.client;
        let mut connector = crate::tls::TlsConnector::new(tls_profile)
            .session_store(self.inner.session_store.clone());
        // `None` => don't advertise ALPS; `Some(bytes)` => advertise + Client EE
        // payload `bytes` (empty for Chrome). Leaving the connector's default
        // (`None`) untouched keeps ALPS off.
        if let Some(payload) = alps_payload {
            connector = connector.alps_payload(payload);
        }

        if client.verify() {
            // verify=true → Strict: every chain/hostname/signature failure
            // aborts the handshake. verify=false → Insecure (explicit opt-out).
            // (webpki cannot distinguish a missing-intermediate from an untrusted
            // root — both are UnknownIssuer — so tolerating incomplete chains
            // would require AIA fetching; that is a separate feature.)
            connector =
                connector.verification_policy(lktls::verify::policy::VerificationPolicy::Strict);
        } else {
            connector = connector.insecure_skip_verify(true);
        }
        connector = connector.require_close_notify(client.require_close_notify());
        if let Some(anchors) = client.custom_ca_anchors() {
            connector = connector.custom_ca_anchors(std::sync::Arc::clone(anchors));
        }
        if let Some(cb) = client.keylog_callback() {
            connector = connector.keylog(cb.clone());
        }

        if let Some(ech_config) = self
            .resolve_ech_config(host, is_remote_dns, dns_https)
            .await
        {
            connector = connector.ech_config(ech_config);
        }

        connector
    }

    /// Resolve the ECHConfigList to offer for `host`: session override, then
    /// client-level, then the DNS HTTPS (SVCB) record.
    ///
    /// Shared by the TCP handshake ([`Self::build_tls_connector`]) and the
    /// QUIC/H3 handshake ([`Self::establish_h3_connection_with_0rtt`]) so the
    /// two transports cannot drift apart on which ECH config a session actually
    /// gets — they did, and a session-level override was silently ignored on
    /// H3 while DNS-discovered ECH never reached it at all.
    ///
    /// `is_remote_dns` gates the DNS level only. On remote-DNS routes (socks5h
    /// / HTTP CONNECT) the proxy resolves the target, so a local HTTPS-RR query
    /// here would leak the target hostname out-of-band from the proxy; the
    /// explicit overrides still apply there.
    ///
    /// `dns_https` says whether this request already ran that query, so the
    /// lookup below happens at most once per request.
    pub(crate) async fn resolve_ech_config(
        &self,
        host: &str,
        is_remote_dns: bool,
        dns_https: DiscoveredHttpsRr<'_>,
    ) -> Option<Vec<u8>> {
        if let Some(ref ech_config) = self.inner.ech_config {
            return Some(ech_config.clone());
        }
        if let Some(ech_config) = self.inner.client.ech_config() {
            return Some(ech_config.to_vec());
        }
        if is_remote_dns {
            return None;
        }

        let ech_bytes = match dns_https {
            // Protocol discovery already queried for this request: reuse its
            // answer (a miss included) rather than querying a second time.
            DiscoveredHttpsRr::Queried(record) => {
                record.and_then(|record| record.ech_config_list.clone())
            }
            DiscoveredHttpsRr::Unqueried => self
                .inner
                .client
                .resolver()
                .lookup_https(host)
                .await
                .ok()
                .flatten()
                .and_then(|record| record.ech_config_list),
        }?;

        tracing::debug!(
            host = %host,
            ech_len = ech_bytes.len(),
            "ech.auto_configured_from_dns",
        );
        Some(ech_bytes)
    }

    /// Build the QUIC crypto configuration from Client + Session settings.
    ///
    /// The H3 sibling of [`Self::build_tls_connector`], and deliberately shaped
    /// like it: same inputs, same verify / custom-CA / ECH / keylog decisions,
    /// so the two transports of one session present the same TLS configuration.
    ///
    /// `host` is the origin (the SNI and the name the certificate is checked
    /// against), which is also the name any ECH config belongs to — never the
    /// alternative endpoint's dial host. `dial_port` is where packets go.
    #[cfg(feature = "quic-h3")]
    pub(crate) async fn build_h3_crypto(
        &self,
        tls_profile: lktls::profile::types::TlsProfile,
        alps_payload: Option<Vec<u8>>,
        host: &str,
        dial_port: u16,
        is_remote_dns: bool,
    ) -> lktls_quic::LktlsQuicClientConfig {
        let client = &self.inner.client;
        let mut crypto = lktls_quic::LktlsQuicClientConfig::new(tls_profile)
            .port(dial_port)
            .session_store(self.inner.session_store.clone());
        if let Some(alps_payload) = alps_payload {
            crypto = crypto.alps_payload(alps_payload);
        }
        if client.verify() {
            // See the TCP path: verify=true → Strict (enforce), verify=false
            // → Insecure (explicit opt-out).
            crypto = crypto.verification_policy(lktls::verify::policy::VerificationPolicy::Strict);
        } else {
            crypto =
                crypto.verification_policy(lktls::verify::policy::VerificationPolicy::Insecure);
        }
        if let Some(anchors) = client.custom_ca_anchors().cloned() {
            crypto = crypto.custom_ca_anchors(anchors);
        }
        // Read the HTTPS RR this request's protocol discovery parked rather
        // than claiming it: a failed QUIC attempt falls back to TCP on the same
        // request, and `establish_connection` still has to find the record
        // there. Nothing is ever parked on remote-DNS routes, and the same gate
        // is kept here so a record parked by a direct-route request can never
        // be applied to a proxied one.
        let discovered_https_rr = if is_remote_dns {
            None
        } else {
            self.peek_discovered_https_rr(host)
        };
        let dns_https = match discovered_https_rr {
            Some(ref record) => DiscoveredHttpsRr::Queried(record.as_ref()),
            None => DiscoveredHttpsRr::Unqueried,
        };
        if let Some(ech) = self
            .resolve_ech_config(host, is_remote_dns, dns_https)
            .await
        {
            crypto = crypto.ech_config(ech);
        }
        if let Some(cb) = client.keylog_callback().cloned() {
            crypto = crypto.keylog(cb);
        }
        crypto
    }

    // -------------------------------------------------------------------
    // Unified connection establishment
    // -------------------------------------------------------------------

    /// Establish a transport connection: TCP → optional TLS → ALPN.
    ///
    /// This is the single entry point for all connection establishment,
    /// used by `establish_and_send`, `streaming`, `preconnect`, and
    /// `websocket`. Each caller provides a [`crate::connect::ConnectConfig`] with the
    /// per-request parameters that vary.
    pub(crate) async fn establish_connection(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&crate::proxy::ProxyConfig>,
        config: &crate::connect::ConnectConfig,
    ) -> crate::error::Result<crate::connect::EstablishedConnection> {
        let client = &self.inner.client;
        let timeouts = client.timeouts();
        let is_remote_dns = crate::protocol::proxy_uses_remote_dns(proxy);

        // Claim the HTTPS RR that protocol discovery already fetched for this
        // request, so the handshake below does not repeat the query — and can
        // not end up with an ECH config that disagrees with the record the H3
        // decision was based on. Claimed *before* the TCP connect so the
        // hand-off window stays as tight as possible.
        //
        // Nothing is ever parked on remote-DNS routes (discovery skips the
        // lookup there), and this side keeps the same gate so a record parked
        // by a direct-route request can never be applied to a proxied one.
        let discovered_https_rr =
            if matches!(config.scheme, crate::connection_pool::Scheme::Https) && !is_remote_dns {
                self.take_discovered_https_rr(host)
            } else {
                None
            };
        let dns_https = match discovered_https_rr {
            Some(ref record) => DiscoveredHttpsRr::Queried(record.as_ref()),
            None => DiscoveredHttpsRr::Unqueried,
        };

        // Phase 1: TCP connect (direct or through proxy, with optional fallback)
        let tcp_start = std::time::Instant::now();
        let tcp_timeout = timeouts.tcp_connect_timeout_or(std::time::Duration::from_secs(10));
        let tcp = crate::connect::connect_tcp(
            host,
            port,
            proxy,
            client.tcp_fingerprint(),
            client.resolver(),
            tcp_timeout,
            Some(self.connection_budget()),
            config,
        )
        .await?;
        let tcp_duration = tcp_start.elapsed();

        tracing::debug!(
            phase = "tcp_connect",
            duration_ms = tcp_duration.as_millis() as u64,
            "http.connect.phase_complete",
        );

        // Phase 2: TLS handshake (only for HTTPS)
        match config.scheme {
            crate::connection_pool::Scheme::Https => {
                let tls_timeout =
                    timeouts.tls_handshake_timeout_or(std::time::Duration::from_secs(10));
                let tls_connector = self
                    .build_tls_connector(
                        config.tls_profile.clone(),
                        config.alps_payload.clone(),
                        host,
                        is_remote_dns,
                        dns_https,
                    )
                    .await;

                let first =
                    crate::connect::wrap_tls(tcp, host, port, &tls_connector, tls_timeout).await;

                // ECH rejected, and the server handed us fresh configs: retry
                // once with them, the way a browser does. The alternative —
                // surfacing the error — would turn a routine key rotation into
                // a hard failure, and ECH is enabled automatically from DNS
                // HTTPS records, so that would hit ordinary traffic. Retrying
                // *without* ECH is not an option: it would leak the very name
                // ECH exists to protect.
                let Some(retry_configs) = ech_retry_configs(&first) else {
                    return first;
                };

                tracing::info!(
                    host = %host,
                    len = retry_configs.len(),
                    "ech.retrying_with_server_configs",
                );

                // The first connection is gone — it was aborted with
                // `ech_required` — so dial again.
                let tcp = crate::connect::connect_tcp(
                    host,
                    port,
                    proxy,
                    client.tcp_fingerprint(),
                    client.resolver(),
                    tcp_timeout,
                    Some(self.connection_budget()),
                    config,
                )
                .await?;

                let retry_connector = self
                    .build_tls_connector(
                        config.tls_profile.clone(),
                        config.alps_payload.clone(),
                        host,
                        is_remote_dns,
                        dns_https,
                    )
                    .await
                    .ech_config(retry_configs);

                // Only one retry: if the server rejects the configs it just
                // supplied, retrying again would loop.
                crate::connect::wrap_tls(tcp, host, port, &retry_connector, tls_timeout).await
            }
            crate::connection_pool::Scheme::Http => {
                let remote_addr = tcp.peer_addr().ok();
                if let Some(addr) = remote_addr {
                    crate::diagnostics::record_remote_addr(addr.to_string());
                }
                Ok(crate::connect::EstablishedConnection::Tcp {
                    stream: crate::connect::TransportStream::plain(tcp),
                    negotiated_alpn: None,
                    remote_addr,
                    negotiated_cipher_suite: None,
                })
            }
        }
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) async fn establish_h3_connection(
        &self,
        host: &str,
        port: u16,
        advertised_host: Option<&str>,
        advertised_port: Option<u16>,
        proxy: Option<&crate::proxy::ProxyConfig>,
    ) -> crate::error::Result<lkh3::H3Connection> {
        self.establish_h3_connection_with_0rtt(
            host,
            port,
            advertised_host,
            advertised_port,
            proxy,
            false,
        )
        .await?
        .into_handshake()
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn establish_h3_connection_with_0rtt(
        &self,
        host: &str,
        port: u16,
        advertised_host: Option<&str>,
        advertised_port: Option<u16>,
        proxy: Option<&crate::proxy::ProxyConfig>,
        allow_0rtt: bool,
    ) -> crate::error::Result<H3ConnectOutcome> {
        let client = &self.inner.client;
        let quic_profile = client.quic_profile().ok_or_else(|| {
            Error::InvalidConfig("HTTP/3 requested but client has no QUIC/H3 profile".into())
        })?;
        let dial_host = advertised_host.unwrap_or(host);
        let dial_port = advertised_port.unwrap_or(port);
        // The alternative endpoint says *where* to send packets, never *who* to
        // authenticate. RFC 7838 §3.1 and RFC 9460 §2.3 both require it to prove
        // it may serve the origin, so the origin host is the SNI and the name
        // the certificate is checked against. Using the alternative's own name
        // let it authenticate as itself — and broke every conforming deployment,
        // since a CDN target presents a certificate for the origin, not for its
        // own internal name.
        let server_name = host;
        tracing::debug!(
            host = %host,
            port,
            dial_host = %dial_host,
            dial_port,
            server_name = %server_name,
            via_proxy = proxy.is_some(),
            "session.h3_connect_start"
        );

        // Remote-DNS routes (socks5h / HTTP CONNECT): the proxy resolves the
        // target, so resolving it locally here would leak the target hostname
        // out-of-band from the proxy. Use the same gate as the TCP path
        // (`build_tls_connector`) so a new route kind can't reintroduce the leak.
        let is_remote_dns = crate::protocol::proxy_uses_remote_dns(proxy);

        let remote_addr = if is_remote_dns {
            None
        } else {
            Some(
                client
                    .resolver()
                    .resolve(dial_host, dial_port)
                    .await
                    .map_err(Error::Io)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        Error::connection(
                            crate::error::ConnectionPhase::DnsResolution,
                            format!(
                                "DNS resolution returned no addresses for {dial_host}:{dial_port}"
                            ),
                            None,
                        )
                    })?,
            )
        };

        let mut tls_profile = client
            .quic_tls_profile()
            .unwrap_or_else(|| client.tls_profile())
            .clone();
        tls_profile.alpn_protocols = vec!["h3".to_string()];
        let alps_payload = if tls_profile.alps_protocols.is_some() {
            tls_profile.alps_protocols = Some(vec!["h3".to_string()]);
            Some(lkh3::encode_alps_h3_settings(&quic_profile.h3))
        } else {
            None
        };

        let crypto = self
            .build_h3_crypto(tls_profile, alps_payload, host, dial_port, is_remote_dns)
            .await;

        let mut quinn_config = crypto.into_quinn();
        let tp = &quic_profile.transport_params;
        let mut transport_config = quinn::TransportConfig::default();
        if tp.max_idle_timeout > 0 {
            transport_config.max_idle_timeout(Some(
                std::time::Duration::from_millis(tp.max_idle_timeout)
                    .try_into()
                    .expect("max_idle_timeout fits in IdleTimeout"),
            ));
        }
        if tp.initial_max_stream_data_bidi_local != tp.initial_max_stream_data_bidi_remote
            || tp.initial_max_stream_data_bidi_local != tp.initial_max_stream_data_uni
        {
            tracing::warn!(
                bidi_local = tp.initial_max_stream_data_bidi_local,
                bidi_remote = tp.initial_max_stream_data_bidi_remote,
                uni = tp.initial_max_stream_data_uni,
                "session.h3_connect: quinn uses a single stream_receive_window for all stream \
                 types; using initial_max_stream_data_bidi_local as the common value"
            );
        }
        transport_config
            .receive_window(
                quinn::VarInt::from_u64(tp.initial_max_data).unwrap_or(quinn::VarInt::MAX),
            )
            .stream_receive_window(
                quinn::VarInt::from_u64(tp.initial_max_stream_data_bidi_local)
                    .unwrap_or(quinn::VarInt::MAX),
            )
            .max_concurrent_bidi_streams(
                quinn::VarInt::from_u64(tp.initial_max_streams_bidi).unwrap_or(quinn::VarInt::MAX),
            )
            .max_concurrent_uni_streams(
                quinn::VarInt::from_u64(tp.initial_max_streams_uni).unwrap_or(quinn::VarInt::MAX),
            );
        if let Some(max_datagram_frame_size) = tp.max_datagram_frame_size {
            let value = usize::try_from(max_datagram_frame_size).unwrap_or(usize::MAX);
            transport_config.datagram_receive_buffer_size(Some(value));
        }
        transport_config
            .send_reserved_transport_parameter(tp.send_reserved_transport_parameter)
            .send_min_ack_delay_transport_parameter(tp.send_min_ack_delay);
        let mut extra_transport_parameters =
            decode_extra_transport_parameters(&tp.extra_transport_parameters)?;
        let mut transport_parameter_order =
            decode_transport_parameter_order(&tp.transport_parameter_order)?;
        if tp.shuffle_transport_parameters {
            // Chrome/BoringSSL randomizes both the GREASE params and the wire
            // order on every connection (capture-verified). Randomize first
            // (patches the order's GREASE-id reference), then shuffle the order.
            randomize_quic_grease_params(
                &mut extra_transport_parameters,
                &mut transport_parameter_order,
            );
            shuffle_transport_parameter_order(&mut transport_parameter_order);
        }
        transport_config
            .extra_transport_parameters(extra_transport_parameters)
            .map_err(|err| {
                Error::InvalidConfig(format!("invalid extra QUIC transport parameter: {err}"))
            })?;
        transport_config
            .transport_parameter_order(transport_parameter_order)
            .map_err(|err| {
                Error::InvalidConfig(format!("invalid QUIC transport parameter order: {err}"))
            })?;
        let packetization = &quic_profile.packetization;
        if let Some(initial_mtu) = packetization.initial_mtu {
            transport_config.initial_mtu(initial_mtu);
        }
        if let Some(initial_datagram_size) = packetization.initial_datagram_size {
            transport_config.initial_datagram_size(initial_datagram_size);
        }
        if packetization.disable_mtu_discovery {
            transport_config.mtu_discovery_config(None);
        }
        transport_config.enable_segmentation_offload(packetization.enable_segmentation_offload);
        transport_config.enable_ecn(packetization.enable_ecn);
        if let Some(layout) = &packetization.initial_frame_layout {
            transport_config.initial_frame_layout(Some(build_initial_frame_layout_config(layout)));
        }
        let actual_active_connection_id_limit = if quic_profile.connection_id_length == 0 {
            2_u64
        } else {
            5_u64
        };
        if tp.active_connection_id_limit != actual_active_connection_id_limit {
            tracing::warn!(
                configured = tp.active_connection_id_limit,
                actual = actual_active_connection_id_limit,
                "session.h3_connect: quinn derives active_connection_id_limit from its CID queue \
                 based on the configured local connection ID length"
            );
        }
        quinn_config.transport_config(Arc::new(transport_config));

        let tcp_timeout = client
            .timeouts()
            .tcp_connect_timeout_or(std::time::Duration::from_secs(10));
        let quic_timeout = client
            .timeouts()
            .quic_connect_timeout
            .unwrap_or(std::time::Duration::from_secs(5));

        let quic_conn = match proxy {
            Some(proxy_cfg)
                if matches!(proxy_cfg.scheme, crate::proxy::ProxyScheme::Socks5 { .. }) =>
            {
                // Keep SOCKS5 UDP ASSOCIATE under the proxy/TCP budget. The
                // QUIC budget should start only once the relay exists and the
                // first QUIC Initial can actually be sent. 0-RTT through this
                // per-relay endpoint is intentionally left for a follow-up.
                self.connect_quic_via_socks5(
                    proxy_cfg,
                    remote_addr,
                    dial_host,
                    dial_port,
                    server_name,
                    quinn_config,
                    client,
                    tcp_timeout,
                    quic_timeout,
                )
                .await?
            }
            Some(proxy_cfg) => {
                // A non-SOCKS5 proxy (e.g. HTTP CONNECT) cannot relay UDP, so
                // there is no way to carry QUIC/H3 through it. Fail loudly rather
                // than silently dialing the origin directly — a direct UDP
                // connection would bypass the proxy and leak the real client IP.
                return Err(Error::InvalidConfig(format!(
                    "HTTP/3 requires a SOCKS5 proxy to relay UDP; proxy scheme {:?} cannot carry QUIC",
                    proxy_cfg.scheme
                )));
            }
            None => {
                let addr = remote_addr.ok_or_else(|| {
                    Error::InvalidConfig(
                        "remote DNS (socks5h) requires a SOCKS5 proxy for QUIC".into(),
                    )
                })?;
                let started = {
                    let mut manager = client.quic_endpoint_manager().lock().await;
                    manager
                        .start_connect(lkquic::ConnectRequest::new(addr, server_name, quinn_config))
                        .await
                        .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                };
                let (connecting, endpoint_guard) = started.into_parts();

                if allow_0rtt {
                    match connecting.into_0rtt() {
                        Ok((quic_conn, accepted)) => {
                            drop(endpoint_guard);
                            tracing::debug!(
                                host = %host,
                                port,
                                "session.h3_connect_0rtt_available"
                            );
                            let h3_conn = tokio::time::timeout(
                                quic_timeout,
                                lkh3::connect_h3_0rtt(quic_conn, &quic_profile.h3, accepted),
                            )
                            .await
                            .map_err(|_| {
                                Error::timeout(
                                    format!(
                                        "HTTP/3 0-RTT control setup to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                    ),
                                    Some(crate::error::ConnectionPhase::H3Negotiation),
                                    Some(quic_timeout),
                                )
                            })?
                            .map_err(|e| {
                                Error::quic(
                                    QuicPhase::Handshake,
                                    format!("H3 0-RTT control setup: {e}"),
                                )
                            })?;
                            return Ok(H3ConnectOutcome::ZeroRtt(h3_conn));
                        }
                        Err(connecting) => {
                            tracing::trace!(
                                host = %host,
                                port,
                                "session.h3_connect_0rtt_unavailable"
                            );
                            tokio::time::timeout(quic_timeout, connecting)
                                .await
                                .map_err(|_| {
                                    Error::timeout(
                                        format!(
                                            "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                        ),
                                        Some(crate::error::ConnectionPhase::QuicHandshake),
                                        Some(quic_timeout),
                                    )
                                })?
                                .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                        }
                    }
                } else {
                    tokio::time::timeout(quic_timeout, connecting)
                        .await
                        .map_err(|_| {
                            Error::timeout(
                                format!(
                                    "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                ),
                                Some(crate::error::ConnectionPhase::QuicHandshake),
                                Some(quic_timeout),
                            )
                        })?
                        .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                }
            }
        };

        let h3_conn = tokio::time::timeout(quic_timeout, lkh3::connect_h3(quic_conn, &quic_profile.h3))
            .await
            .map_err(|_| {
                Error::timeout(
                    format!(
                        "HTTP/3 control setup to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::QuicHandshake),
                    Some(quic_timeout),
                )
            })?
            .map_err(|e| Error::quic(QuicPhase::Handshake, format!("H3 control setup: {e}")))?;
        tracing::debug!(
            host = %host,
            port,
            remote = ?remote_addr,
            pseudo_order = %quic_profile.h3.pseudo_header_order_token(),
            "session.h3_connect_ready"
        );
        Ok(H3ConnectOutcome::Handshake(h3_conn))
    }

    /// Establish a QUIC connection through a SOCKS5 UDP relay.
    ///
    /// The TCP control connection from UDP ASSOCIATE is owned by the
    /// `Socks5UdpSocket` which is held by `Arc` inside the quinn `Endpoint`.
    /// When the QUIC connection (and its endpoint) is dropped, the control
    /// connection is closed automatically, invalidating the relay.
    ///
    /// For `socks5h://` (remote DNS), `remote_addr` may be `None` — DNS is
    /// resolved by the proxy and the domain name is embedded in every UDP
    /// datagram header (ATYP=0x03).
    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    async fn connect_quic_via_socks5(
        &self,
        proxy_cfg: &crate::proxy::ProxyConfig,
        remote_addr: Option<std::net::SocketAddr>,
        dial_host: &str,
        dial_port: u16,
        server_name: &str,
        quinn_config: quinn::ClientConfig,
        client: &crate::client::Client,
        proxy_timeout: std::time::Duration,
        quic_timeout: std::time::Duration,
    ) -> crate::error::Result<quinn::Connection> {
        use crate::proxy::socks5_udp::{Socks5UdpSocket, SocksTarget};

        let tcp_fp = client.tcp_fingerprint();
        let resolver = client.resolver();
        let (proxy_host, proxy_port) = proxy_cfg.host_port();

        tracing::debug!(
            proxy = %format_args!("{proxy_host}:{proxy_port}"),
            target = %format_args!("{dial_host}:{dial_port}"),
            server_name = %server_name,
            remote_dns = remote_addr.is_none(),
            proxy_timeout_ms = proxy_timeout.as_millis() as u64,
            quic_timeout_ms = quic_timeout.as_millis() as u64,
            "quic.socks5_connect_prepare"
        );

        let associate = tokio::time::timeout(proxy_timeout, proxy_cfg.udp_associate(tcp_fp, resolver))
            .await
            .map_err(|_| {
                Error::timeout(
                    format!(
                        "SOCKS5 UDP ASSOCIATE to {proxy_host}:{proxy_port} timed out after {proxy_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::ProxyTunnel),
                    Some(proxy_timeout),
                )
            })
            .and_then(|inner| inner);

        let assoc = match associate {
            Ok(value) => value,
            Err(error) => {
                // UDP ASSOCIATE failed *before* any QUIC bytes ever hit the
                // wire — this is a property of the proxy, not the origin.
                // Quarantine the entire route so the next request to *any*
                // origin via this proxy skips H3 immediately and falls
                // through to H2 without paying another ~proxy_timeout.
                let route = crate::protocol::RouteKey::from_proxy(Some(proxy_cfg));
                self.broken_quic_tracker()
                    .mark_route_broken(&route, crate::alt_svc::BrokenReason::ProxyUdpUnavailable);
                tracing::warn!(
                    proxy = %format_args!("{proxy_host}:{proxy_port}"),
                    target = %format_args!("{dial_host}:{dial_port}"),
                    error = %error,
                    "quic.socks5_udp_associate_failed_route_quarantined"
                );
                return Err(error);
            }
        };

        // `first_relay` is hop1's relay (unspecified BND already resolved in
        // `udp_associate`) — the only address datagrams are sent to directly.
        // `inner_relays` are the chain's inner-hop relays, stacked as nested
        // headers. `control_conns` holds every hop's control TCP connection.
        let relay_addr = assoc.first_relay;
        let intermediate_relays = assoc.inner_relays;

        let bind_addr: std::net::SocketAddr = if relay_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let local_udp = tokio::net::UdpSocket::bind(bind_addr).await.map_err(|e| {
            Error::quic(
                QuicPhase::Handshake,
                format!("failed to bind local UDP for SOCKS5 relay: {e}"),
            )
        })?;
        let local_udp_addr = local_udp.local_addr().ok();

        let target = match remote_addr {
            Some(addr) => SocksTarget::Ip(addr),
            None => SocksTarget::Domain {
                host: dial_host.to_string(),
                port: dial_port,
            },
        };

        let socks5_socket = Arc::new(Socks5UdpSocket::new(
            local_udp,
            relay_addr,
            intermediate_relays,
            target,
            assoc.control_conns,
        ));

        let quinn_addr = socks5_socket.quinn_addr();

        tracing::debug!(
            local_udp = ?local_udp_addr,
            relay = %relay_addr,
            quinn_addr = %quinn_addr,
            remote_dns = remote_addr.is_none(),
            "quic.socks5_relay_ready"
        );

        let manager = client.quic_endpoint_manager().lock().await;
        let backend = manager.backend();
        let endpoint = backend
            .create_endpoint_with_socket(
                socks5_socket as Arc<dyn quinn::AsyncUdpSocket>,
                manager.cid_len(),
                manager.endpoint_max_udp_payload_size(),
                manager.grease_quic_bit_enabled(),
                manager.endpoint_initial_destination_cid_len(),
            )
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?;

        tracing::debug!(
            quinn_addr = %quinn_addr,
            relay = %relay_addr,
            remote_dns = remote_addr.is_none(),
            "quic.socks5_connect_start"
        );

        let connecting = endpoint
            .connect_with(quinn_config, quinn_addr, server_name)
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?;

        tracing::debug!(
            target = %format_args!("{dial_host}:{dial_port}"),
            server_name = %server_name,
            "quic.socks5_handshake_waiting"
        );

        tokio::time::timeout(quic_timeout, connecting)
            .await
            .map_err(|_| {
                tracing::warn!(
                    target = %format_args!("{dial_host}:{dial_port}"),
                    server_name = %server_name,
                    timeout_ms = quic_timeout.as_millis() as u64,
                    "quic.socks5_handshake_timeout"
                );
                Error::timeout(
                    format!(
                        "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::QuicHandshake),
                    Some(quic_timeout),
                )
            })?
            .inspect(|_| {
                tracing::debug!(
                    target = %format_args!("{dial_host}:{dial_port}"),
                    server_name = %server_name,
                    "quic.socks5_connect_established"
                );
            })
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))
    }

    #[cfg(feature = "quic-h3")]
    fn preconnect_h3<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        conn_key: &'a crate::connection_pool::ConnectionKey,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a crate::proxy::ProxyConfig>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::error::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            let permit = self.reserve_connection()?;
            let h3_conn = match self
                .establish_h3_connection(
                    host,
                    port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy,
                )
                .await
            {
                Ok(h3_conn) => h3_conn,
                Err(error) => {
                    self.broken_quic_tracker()
                        .mark_broken_for_route(&discovery.route, &discovery.origin);
                    self.alt_svc_cache()
                        .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    return Err(error);
                }
            };

            self.broken_quic_tracker()
                .mark_working_for_route(&discovery.route, &discovery.origin);
            // Successful H3 over this route also proves the proxy can
            // carry UDP, so clear any prior `ProxyUdpUnavailable` mark.
            self.broken_quic_tracker()
                .mark_route_working(&discovery.route);
            self.alt_svc_cache()
                .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
            let (sender, driver) = h3_conn.into_parts();
            let mut pool = self.inner.pool.lock();
            pool.insert_h3_reserved(conn_key.clone(), sender, driver, permit);
            Ok(())
        })
    }

    fn preconnect_tcp<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        scheme: crate::connection_pool::Scheme,
        conn_key: &'a crate::connection_pool::ConnectionKey,
        proxy: Option<crate::proxy::ProxyConfig>,
        preferred_http_version: PreferredHttpVersion,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::error::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            let permit = self.reserve_connection()?;
            let client = &self.inner.client;
            let connect_config =
                pipeline::build_connect_config(client, preferred_http_version, scheme);

            let conn = self
                .establish_connection(host, port, proxy.as_ref(), &connect_config)
                .await?;

            let use_h2 = pipeline::should_use_h2(conn.negotiated_alpn(), preferred_http_version)?;

            if use_h2 {
                let h2_conn = crate::h2::connect_h2_with_config(
                    conn.into_tcp_stream()?,
                    client.h2_profile(),
                    None,
                    client.max_pending_h2_requests(),
                )
                .await?;
                let mut pool = self.inner.pool.lock();
                pool.insert_h2_reserved(
                    conn_key.clone(),
                    h2_conn.clone_sender(),
                    h2_conn.into_task(),
                    permit,
                );
            } else {
                let mut builder = hyper::client::conn::http1::Builder::new();
                builder.title_case_headers(true).preserve_header_case(true);
                let (sender, conn_driver) = builder
                    .handshake::<
                        crate::connect::TransportStream,
                        http_body_util::Full<bytes::Bytes>,
                    >(conn.into_tcp_stream()?)
                    .await
                    .map_err(|e| {
                        crate::error::Error::Http(format!(
                            "preconnect HTTP/1.1 handshake failed: {e}"
                        ))
                    })?;

                let conn_task = tokio::spawn(async move {
                    if let Err(e) = conn_driver.await {
                        tracing::debug!(error = %e, "preconnect.h1_connection_closed");
                    }
                });
                let mut pool = self.inner.pool.lock();
                pool.insert_h1_reserved(conn_key.clone(), sender, conn_task, permit);
            }

            Ok(())
        })
    }

    // -------------------------------------------------------------------
    // Request builders
    // -------------------------------------------------------------------

    /// Start building a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::GET, url)
    }

    /// Start building a request with an explicit HTTP method.
    pub fn request(&self, method: http::Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url)
    }

    /// Start building a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::POST, url)
    }

    /// Start building a PUT request.
    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::PUT, url)
    }

    /// Start building a DELETE request.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::DELETE, url)
    }

    /// Start building a HEAD request.
    pub fn head(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::HEAD, url)
    }

    /// Start building a PATCH request.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::PATCH, url)
    }

    /// Start building an OPTIONS request.
    pub fn options(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::OPTIONS, url)
    }

    /// Pre-establish a connection to the given URL.
    ///
    /// Completes DNS resolution, TCP connect, TLS handshake (for HTTPS),
    /// and HTTP/2 SETTINGS exchange (if applicable), then stores the ready
    /// connection in the session's connection pool.  Subsequent requests to
    /// the same `host:port` will reuse this connection, eliminating
    /// cold-start latency.
    ///
    /// If a pooled connection for this origin already exists, this method
    /// returns immediately without creating a new one.
    ///
    /// Both `https://` and `http://` URLs are supported. For HTTP, only a
    /// TCP connect and HTTP/1.1 handshake are performed (no TLS).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # let client = Client::default();
    /// # let session = client.session().build();
    /// session.preconnect("https://api.example.com").await?;
    /// session.preconnect("http://legacy-api.example.com").await?;
    /// // subsequent requests reuse the pre-warmed connections
    /// let resp = session.get("https://api.example.com/data").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn preconnect(&self, url: &str) -> crate::error::Result<()> {
        use crate::connection_pool::{ConnectionKey, Scheme};

        let parsed =
            Url::parse(url).map_err(|e| crate::error::Error::UrlParse(format!("{url}: {e}")))?;

        let scheme = match parsed.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            other => {
                return Err(crate::error::Error::UrlParse(format!(
                    "preconnect: unsupported scheme: {other}"
                )));
            }
        };

        let host = parsed
            .host_str()
            .ok_or_else(|| crate::error::Error::UrlParse("missing host".into()))?
            .to_string();

        let port = parsed.port_or_known_default().unwrap_or(match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        });

        let route = crate::protocol::RouteKey::from_proxy(self.inner.proxy.as_ref());
        let conn_key = ConnectionKey {
            scheme,
            host: Arc::from(host.as_str()),
            port,
            route,
        };

        // Skip if a connection already exists — uses has_connection() to
        // avoid the H1 connection leak that try_acquire() would cause.
        let protocol_policy = self.inner.protocol_policy.clone();
        let preferred_http_version = pipeline::effective_http_version(None, &protocol_policy, self);
        pipeline::log_protocol_policy(
            &conn_key.route,
            &host,
            port,
            &protocol_policy,
            preferred_http_version,
        );
        {
            let mut pool = self.inner.pool.lock();
            let already_warmed = match preferred_http_version {
                PreferredHttpVersion::Auto => pool.has_connection(&conn_key),
                PreferredHttpVersion::Http1Only => pool.has_h1_connection(&conn_key),
                PreferredHttpVersion::Http2Only => pool.has_h2_connection(&conn_key),
                PreferredHttpVersion::Http3Only | PreferredHttpVersion::Http3WithFallback => {
                    pool.has_h3_connection(&conn_key)
                }
            };
            if already_warmed {
                return Ok(());
            }
        }

        let effective_proxy = self.inner.proxy.clone();
        if preferred_http_version == PreferredHttpVersion::Http3Only
            && self.inner.client.quic_profile().is_none()
        {
            return Err(Error::InvalidConfig(
                "HTTP/3 requested but client has no QUIC/H3 profile".into(),
            ));
        }
        let quic_discovery = pipeline::discover_quic_support(
            self,
            scheme,
            &host,
            port,
            effective_proxy.as_ref(),
            &protocol_policy,
            preferred_http_version,
        )
        .await;
        pipeline::log_quic_discovery(&quic_discovery);
        let decision =
            pipeline::decide_protocol(preferred_http_version, &protocol_policy, &quic_discovery);
        pipeline::log_protocol_decision(&quic_discovery, &protocol_policy, decision);

        match decision {
            pipeline::ProtocolDecision::Tcp => {
                self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy,
                    preferred_http_version,
                )
                .await?;
                let schedule_probe =
                    pipeline::should_background_probe(&protocol_policy, &quic_discovery);
                pipeline::log_background_probe_decision(
                    &conn_key.route,
                    &host,
                    port,
                    &protocol_policy,
                    &quic_discovery,
                    schedule_probe,
                );
                if schedule_probe {
                    self.spawn_background_quic_probe(
                        host.clone(),
                        port,
                        conn_key.clone(),
                        quic_discovery.clone(),
                        self.inner.proxy.clone(),
                    );
                }
            }
            #[cfg(feature = "quic-h3")]
            pipeline::ProtocolDecision::Quic => {
                self.preconnect_h3(
                    &host,
                    port,
                    &conn_key,
                    &quic_discovery,
                    effective_proxy.as_ref(),
                )
                .await?;
            }
            #[cfg(feature = "quic-h3")]
            pipeline::ProtocolDecision::Race => {
                let race_cfg = pipeline::protocol_policy_chrome_like_config(
                    &protocol_policy,
                    self.chrome_like_protocol_config(),
                );
                let quic_proxy = effective_proxy.clone();
                let mut quic_future = self.preconnect_h3(
                    &host,
                    port,
                    &conn_key,
                    &quic_discovery,
                    quic_proxy.as_ref(),
                );

                if !race_cfg.tcp_main_job_delay.is_zero() {
                    let mut tcp_delay =
                        std::pin::pin!(tokio::time::sleep(race_cfg.tcp_main_job_delay));
                    tokio::select! {
                        biased;

                        quic_result = &mut quic_future => match quic_result {
                            Ok(()) => {
                                if race_cfg.keep_tcp_probe_after_quic_win {
                                    self.spawn_background_tcp_probe(
                                        host.clone(),
                                        port,
                                        scheme,
                                        conn_key.clone(),
                                        effective_proxy.clone(),
                                        preferred_http_version,
                                    );
                                }
                                tracing::debug!(host = %host, port = port, "session.preconnect_complete");
                                return Ok(());
                            }
                            Err(quic_error) => {
                                tracing::warn!(
                                    error = %quic_error,
                                    fallback = "quic_to_tcp",
                                    "preconnect.h3_race_failed_before_tcp_release",
                                );
                                match self.preconnect_tcp(
                                    &host,
                                    port,
                                    scheme,
                                    &conn_key,
                                    effective_proxy,
                                    preferred_http_version,
                                )
                                .await {
                                    Ok(()) => {
                                        tracing::debug!(host = %host, port = port, "session.preconnect_complete");
                                        return Ok(());
                                    }
                                    Err(tcp_error) => {
                                        return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                                    }
                                }
                            }
                        },
                        _ = &mut tcp_delay => {}
                    }
                }

                let mut tcp_future = self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy.clone(),
                    preferred_http_version,
                );

                tokio::select! {
                    biased;

                    quic_result = &mut quic_future => match quic_result {
                        Ok(()) => {
                            if race_cfg.keep_tcp_probe_after_quic_win {
                                self.spawn_background_tcp_probe(
                                    host.clone(),
                                    port,
                                    scheme,
                                    conn_key.clone(),
                                    effective_proxy.clone(),
                                    preferred_http_version,
                                );
                            }
                        }
                        Err(quic_error) => {
                            tracing::warn!(
                                error = %quic_error,
                                fallback = "quic_to_tcp",
                                "preconnect.h3_race_failed_waiting_for_tcp",
                            );
                            match tcp_future.await {
                                Ok(()) => {}
                                Err(tcp_error) => {
                                    return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                                }
                            }
                        }
                    },
                    tcp_result = &mut tcp_future => match tcp_result {
                        Ok(()) => {
                            if race_cfg.keep_quic_probe_after_tcp_win {
                                self.spawn_background_quic_probe(
                                    host.clone(),
                                    port,
                                    conn_key.clone(),
                                    quic_discovery.clone(),
                                    effective_proxy.clone(),
                                );
                            }
                        }
                        Err(tcp_error) => match quic_future.await {
                            Ok(()) => {}
                            Err(quic_error) => {
                                return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                            }
                        },
                    },
                }
            }
            #[cfg(not(feature = "quic-h3"))]
            pipeline::ProtocolDecision::Race => {
                self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy,
                    preferred_http_version,
                )
                .await?;
            }
            #[cfg(not(feature = "quic-h3"))]
            pipeline::ProtocolDecision::Quic => {
                return Err(Error::InvalidConfig(
                    "QUIC/H3 support is not compiled in; enable the `quic-h3` feature".into(),
                ));
            }
        }

        tracing::debug!(host = %host, port = port, "session.preconnect_complete");
        Ok(())
    }

    /// Pre-establish connections to multiple URLs concurrently.
    ///
    /// Each URL is preconnected independently.  Errors for individual URLs
    /// do not affect the others.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # let client = Client::default();
    /// # let session = client.session().build();
    /// let results = session.preconnect_many(&[
    ///     "https://api.example.com",
    ///     "https://cdn.example.com",
    /// ]).await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn preconnect_many(&self, urls: &[&str]) -> Vec<crate::error::Result<()>> {
        let mut handles = Vec::with_capacity(urls.len());
        for url in urls {
            let session = self.clone();
            let url = url.to_string();
            handles.push(tokio::spawn(async move { session.preconnect(&url).await }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.unwrap_or_else(|e| {
                Err(crate::error::Error::Http(format!(
                    "preconnect task panicked: {e}"
                )))
            }));
        }
        results
    }

    /// Start building a WebSocket connection.
    ///
    /// Supports both `wss://` (TLS) and `ws://` schemes, and automatically
    /// selects HTTP/1.1 Upgrade or HTTP/2 Extended CONNECT based on ALPN.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_144()).build();
    /// # let session = client.session().build();
    /// let mut ws = session.websocket("wss://echo.websocket.events")
    ///     .header("Origin", "https://echo.websocket.events")
    ///     .connect()
    ///     .await?;
    ///
    /// ws.send_text("hello").await?;
    /// let msg = ws.recv().await?;
    /// ws.close(None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn websocket(&self, url: &str) -> crate::ws::builder::WsBuilder {
        crate::ws::builder::WsBuilder::new_with_session(url, self.clone())
    }
}

// ---------------------------------------------------------------------------
// Session Builder
// ---------------------------------------------------------------------------

/// Preferred HTTP version for a session or request.
///
/// This is a request-side preference type. For the version observed on a
/// response, use [`crate::NegotiatedHttpVersion`] via
/// [`crate::Response::negotiated_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredHttpVersion {
    /// Use whatever the server negotiates via ALPN and policy defaults.
    Auto,
    /// Force HTTP/1.1 only (do not use HTTP/2 even if negotiated).
    Http1Only,
    /// Force HTTP/2 only (fail if server doesn't support H2).
    Http2Only,
    /// Force HTTP/3 only.
    Http3Only,
    /// Prefer HTTP/3 and fall back to TCP-based HTTP if QUIC fails.
    Http3WithFallback,
}

impl From<HttpVersion> for PreferredHttpVersion {
    fn from(version: HttpVersion) -> Self {
        match version {
            HttpVersion::Http10 | HttpVersion::Http11 => Self::Http1Only,
            HttpVersion::H2 => Self::Http2Only,
            HttpVersion::H3 => Self::Http3Only,
            HttpVersion::Unknown => Self::Auto,
        }
    }
}

/// How lkrequest chooses between TCP-based HTTP and QUIC/H3 when both are viable.
///
/// This only affects mixed-protocol selection in [`PreferredHttpVersion::Auto`].
/// Explicit session/request overrides such as `http1_only()`, `http2_only()`,
/// `http3_only()`, and `http3_with_fallback()` keep their existing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolSelectionPolicy {
    /// Current lkrequest behavior: once QUIC/H3 is discovered as usable, go
    /// straight to QUIC instead of racing a TCP connection.
    #[default]
    Deterministic,
    /// Chrome-like behavior: when `Auto` mode has a viable H3 candidate
    /// (Alt-Svc / HTTPS DNS), race TCP and QUIC and use whichever path
    /// completes first.
    ChromeLike,
}

/// Tunables for [`ProtocolSelectionPolicy::ChromeLike`].
///
/// Chromium's "main TCP job" delay is dynamic and context-dependent. lkrequest
/// models it with a fixed QUIC head-start and explicit loser-probe toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromeLikeProtocolConfig {
    /// Fixed delay before the TCP path is allowed to compete with QUIC.
    ///
    /// If QUIC fails before this delay expires, TCP starts immediately.
    pub tcp_main_job_delay: std::time::Duration,
    /// When TCP wins the race, keep probing QUIC in the background and update
    /// the broken-QUIC tracker / H3 pool from that outcome.
    pub keep_quic_probe_after_tcp_win: bool,
    /// When QUIC wins the race, optionally keep probing the TCP path in the
    /// background to warm the H1/H2 pool.
    pub keep_tcp_probe_after_quic_win: bool,
}

impl Default for ChromeLikeProtocolConfig {
    fn default() -> Self {
        Self {
            tcp_main_job_delay: std::time::Duration::from_millis(300),
            keep_quic_probe_after_tcp_win: true,
            keep_tcp_probe_after_quic_win: false,
        }
    }
}

fn apply_legacy_protocol_policy_overrides(
    policy: &mut ProtocolPolicy,
    preferred_http_version: PreferredHttpVersion,
    protocol_selection_policy: ProtocolSelectionPolicy,
    chrome_like_protocol_config: ChromeLikeProtocolConfig,
) {
    match preferred_http_version {
        PreferredHttpVersion::Http1Only | PreferredHttpVersion::Http2Only => {
            policy.intent = HttpIntent::H2Only;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            policy.upgrade = crate::protocol::UpgradePolicy::Off;
            policy.fallback = FallbackPolicy::NoFallback;
        }
        PreferredHttpVersion::Http3Only => {
            policy.intent = HttpIntent::H3Only;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            policy.fallback = FallbackPolicy::NoFallback;
        }
        PreferredHttpVersion::Http3WithFallback => {
            policy.intent = HttpIntent::AcquireH3WhenViable;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            if matches!(policy.fallback, FallbackPolicy::NoFallback) {
                policy.fallback = FallbackPolicy::AllowFallbackOnNetworkErrors;
            }
        }
        PreferredHttpVersion::Auto => {}
    }

    match protocol_selection_policy {
        ProtocolSelectionPolicy::Deterministic => {
            if matches!(policy.acquisition, AcquisitionPolicy::Race(_))
                && preferred_http_version == PreferredHttpVersion::Auto
            {
                policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            }
        }
        ProtocolSelectionPolicy::ChromeLike => {
            policy.acquisition = AcquisitionPolicy::Race(RacePolicy {
                enable_tcp: true,
                enable_quic: true,
                tcp_delay: chrome_like_protocol_config.tcp_main_job_delay,
                quic_delay: std::time::Duration::ZERO,
                only_when_h3_advertised: true,
            });
        }
    }
}

/// Builder for constructing a [`Session`].
pub struct SessionBuilder {
    client: Client,
    proxy: Option<ProxyConfig>,
    redirect_policy: RedirectPolicy,
    https_only: bool,
    hsts_policy: Option<Arc<dyn crate::hsts::HstsPolicy>>,
    retry_policy: Option<Arc<dyn RetryPolicy>>,
    ech_config: Option<Vec<u8>>,
    middlewares: crate::middleware::MiddlewareStack,
    protocol_policy: Option<ProtocolPolicy>,
    preferred_http_version: Option<PreferredHttpVersion>,
    protocol_selection_policy: Option<ProtocolSelectionPolicy>,
    chrome_like_protocol_config: Option<ChromeLikeProtocolConfig>,
    default_accept_encoding: Option<AcceptEncoding>,
    max_connections_override: Option<usize>,
    idle_timeout: Option<std::time::Duration>,
    header_order: Option<Vec<http::header::HeaderName>>,
    h3_header_order: Option<Vec<http::header::HeaderName>>,
    cookie_order: Option<Vec<Box<str>>>,
    broken_quic_policy: Option<BrokenQuicPolicy>,
    network_partition_context: Option<NetworkPartitionContext>,
}

impl SessionBuilder {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            proxy: None,
            redirect_policy: RedirectPolicy::default(),
            https_only: false,
            hsts_policy: None,
            retry_policy: None,
            ech_config: None,
            middlewares: Vec::new(),
            protocol_policy: None,
            preferred_http_version: None,
            protocol_selection_policy: None,
            chrome_like_protocol_config: None,
            default_accept_encoding: None,
            max_connections_override: None,
            idle_timeout: None,
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            broken_quic_policy: None,
            network_partition_context: None,
        }
    }

    /// Set the proxy for this session from a URL string.
    ///
    /// All requests from this session will go through this proxy by default.
    pub fn proxy(mut self, proxy_url: &str) -> Self {
        match ProxyConfig::parse(proxy_url) {
            Ok(config) => self.proxy = Some(config),
            Err(e) => {
                tracing::warn!(url = %proxy_url, error = %e, "session.invalid_proxy_url");
            }
        }
        self
    }

    /// Set the proxy from a `ProxyConfig`.
    pub fn proxy_config(mut self, config: ProxyConfig) -> Self {
        self.proxy = Some(config);
        self
    }

    /// Set the maximum number of redirects to follow (default: 10).
    ///
    /// Equivalent to `redirect_policy(RedirectPolicy::Follow(n))`.
    /// Use `redirect_policy(RedirectPolicy::None)` to disable redirect following.
    pub fn max_redirects(mut self, n: u32) -> Self {
        self.redirect_policy = RedirectPolicy::Follow(n);
        self
    }

    /// Set the redirect policy for this session.
    ///
    /// - `RedirectPolicy::Follow(n)` — automatically follow up to `n` redirects (default: 10).
    /// - [`RedirectPolicy::None`] — do not follow redirects; return the 3xx response as-is.
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Refuse to follow redirects that leave HTTPS (a downgrade to `http://`).
    ///
    /// Default is `false`, matching Chrome's network stack and the reqwest/curl
    /// defaults: a scheme downgrade is followed, and HSTS pre-upgrade is the
    /// real protection. Set to `true` to opt into refusing any redirect to a
    /// non-HTTPS URL — analogous to reqwest's `https_only` / curl's
    /// `--proto-redir`. Leaving it off keeps behavior byte-identical to Chrome.
    pub fn https_only(mut self, yes: bool) -> Self {
        self.https_only = yes;
        self
    }

    /// Set the HSTS / scheme-upgrade policy for this session.
    ///
    /// Decides whether an `http://` URL (initial request or redirect target) is
    /// upgraded to `https://` before connecting — the customizable equivalent
    /// of a browser's HSTS handling. The default is
    /// [`NoHsts`](crate::hsts::NoHsts): a fresh session is a stateless first
    /// visit, so nothing is upgraded. Built-ins include
    /// [`StaticHsts`](crate::hsts::StaticHsts) and
    /// [`DynamicHsts`](crate::hsts::DynamicHsts); a `Fn(&str) -> bool` closure
    /// also works. See [`crate::hsts`] for the full rationale.
    pub fn hsts_policy(mut self, policy: impl crate::hsts::HstsPolicy + 'static) -> Self {
        self.hsts_policy = Some(Arc::new(policy));
        self
    }

    /// Set a retry policy for failed requests.
    ///
    /// When set, requests that fail with retryable errors or return retryable
    /// status codes will be automatically retried according to the policy.
    ///
    /// # Idempotency / replay safety
    ///
    /// Error-based retries are gated on whether the request is **safe to
    /// replay**, so a non-idempotent request is never silently re-sent after a
    /// failure that may have already reached the server (RFC 9110 §9.2.2):
    ///
    /// - **Safe methods** (`GET`/`HEAD`/`OPTIONS`/`TRACE`) — always retried.
    /// - **Non-idempotent methods** (`POST`/`PUT`/`PATCH`/`DELETE`, custom
    ///   methods) — retried **only** when the failure proves the request was
    ///   never processed (connection-establishment failures, HTTP/2
    ///   `REFUSED_STREAM`). A timeout, reset, or GOAWAY that occurs *after* the
    ///   request was transmitted surfaces the error instead of replaying it,
    ///   to avoid duplicate side effects (e.g. a double `POST`).
    /// - To opt a non-idempotent request back into full retry/replay (e.g. it
    ///   carries an `Idempotency-Key`), set
    ///   [`RequestBuilder::idempotency`](crate::session::RequestBuilder::idempotency)
    ///   to [`Idempotency::Idempotent`] on that request.
    ///
    /// Retryable **status-code** responses are gated the same way. The server
    /// answered, so the request certainly arrived; a non-idempotent method is
    /// therefore replayed only on a status that says the request was *not
    /// applied*:
    ///
    /// - **Replayed** — `429 Too Many Requests` and `503 Service Unavailable`:
    ///   both mean the server refused the request rather than handling it.
    /// - **Returned to the caller** — `502`, `504` and the Cloudflare
    ///   `520`–`530` range. A `502` means a gateway got a bad answer from the
    ///   origin, which may already have applied the request; the `52x` range
    ///   mixes "never reached the origin" with plain timeouts. Replaying a
    ///   `POST` on those risks a duplicate charge or order.
    ///
    /// **Behaviour change:** these statuses used to be replayed regardless of
    /// method. To restore that for a request you know is safe to duplicate, set
    /// [`RequestBuilder::idempotency`](crate::session::RequestBuilder::idempotency)
    /// to [`Idempotency::Idempotent`].
    ///
    /// See [`Idempotency`], [`crate::retry::retry_is_replay_safe`] and
    /// [`crate::retry::status_retry_is_replay_safe`] for the exact rules.
    pub fn retry_policy(mut self, policy: impl RetryPolicy + 'static) -> Self {
        self.retry_policy = Some(Arc::new(policy));
        self
    }

    /// Add a middleware to the session-level middleware stack.
    ///
    /// Session middlewares are applied after client-level middlewares on the
    /// request path, and before them on the response path (onion model).
    ///
    /// # Example
    ///
    /// ```text
    /// let session = client.session()
    ///     .middleware(AuthInjector::new("Bearer xxx"))
    ///     .build();
    /// ```
    pub fn middleware(mut self, mw: impl crate::middleware::Middleware + 'static) -> Self {
        self.middlewares.push(Arc::new(mw));
        self
    }

    /// Set an ECHConfigList for this session (raw DER bytes).
    ///
    /// When set, all TLS connections from this session will use this
    /// ECHConfig, overriding the client-level `ech_config`.
    ///
    /// Typical use: store `ech_retry_configs` from a previous connection
    /// and apply them to the same session for subsequent requests.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let ech_config_from_dns = vec![];
    /// let session = client.session()
    ///     .ech_config(ech_config_from_dns)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.ech_config = Some(config_list);
        self
    }

    /// Override the session's runtime protocol behavior.
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy = Some(policy);
        self
    }

    /// Override only the session's high-level H2/H3 intent.
    pub fn http_intent(mut self, intent: HttpIntent) -> Self {
        let policy = self
            .protocol_policy
            .take()
            .unwrap_or_else(|| self.client.protocol_policy().clone())
            .with_intent(intent);
        self.protocol_policy = Some(policy);
        self
    }

    /// Force this session to only use HTTP/1.1.
    ///
    /// HTTP/1.1 connections are exclusive and are not capped by the default
    /// session connection budget. Use [`SessionBuilder::max_connections`]
    /// when an explicit H1 connection limit is required.
    ///
    /// Even if the server negotiates HTTP/2 via ALPN, requests will be
    /// sent using HTTP/1.1. Useful when a target site has stricter
    /// fingerprint checks on H2 or when H1.1 is required for compatibility.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// let session = client.session()
    ///     .http1_only()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn http1_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http1Only);
        self
    }

    /// Force this session to only use HTTP/2.
    ///
    /// If the server does not negotiate HTTP/2 via ALPN, the connection
    /// will fail. Useful when you know the target supports H2 and want
    /// consistent H2 fingerprinting.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// let session = client.session()
    ///     .http2_only()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn http2_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http2Only);
        self
    }

    /// Force this session to only use HTTP/3.
    pub fn http3_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http3Only);
        self
    }

    /// Prefer HTTP/3 but fall back to TCP-based HTTP on QUIC failure.
    pub fn http3_with_fallback(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http3WithFallback);
        self
    }

    /// Set how `Auto` mode chooses between TCP and QUIC when both are viable.
    ///
    /// The default is [`ProtocolSelectionPolicy::Deterministic`]. Use
    /// [`ProtocolSelectionPolicy::ChromeLike`] to mimic Chromium's
    /// "main TCP job + alternative QUIC job" racing model when H3 has already
    /// been discovered via Alt-Svc or HTTPS DNS records.
    pub fn protocol_selection_policy(mut self, policy: ProtocolSelectionPolicy) -> Self {
        self.protocol_selection_policy = Some(policy);
        self
    }

    /// Set tunables for [`ProtocolSelectionPolicy::ChromeLike`].
    pub fn chrome_like_protocol_config(mut self, config: ChromeLikeProtocolConfig) -> Self {
        self.chrome_like_protocol_config = Some(config);
        self
    }

    /// Set the default `Accept-Encoding` for all requests in this session.
    ///
    /// When set, the `Accept-Encoding` header will be automatically added
    /// to requests (unless overridden per-request). Response bodies will
    /// be decompressed accordingly.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// let session = client.session()
    ///     .default_accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn default_accept_encoding(mut self, encoding: AcceptEncoding) -> Self {
        self.default_accept_encoding = Some(encoding);
        self
    }

    /// Set the maximum connections for this session (overrides client-level).
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections_override = Some(n);
        self
    }

    /// Set the idle connection timeout (default: 90 seconds).
    ///
    /// Connections that have been idle longer than this duration are
    /// automatically evicted from the pool on the next acquire/check.
    pub fn idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Set the header sending order template for this session.
    ///
    /// Overrides the client-level header_order for all requests in this session.
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.header_order = Some(names);
        }
        self
    }

    /// Set the header sending order from pre-parsed HeaderNames.
    pub fn header_order_from_names(mut self, order: Vec<http::header::HeaderName>) -> Self {
        if !order.is_empty() {
            self.header_order = Some(order);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order template for this session.
    ///
    /// Overrides the client-level `h3_header_order` for H3 requests only.
    pub fn h3_header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.h3_header_order = Some(names);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order from pre-parsed HeaderNames.
    pub fn h3_header_order_from_names(mut self, order: Vec<http::header::HeaderName>) -> Self {
        if !order.is_empty() {
            self.h3_header_order = Some(order);
        }
        self
    }

    /// Set the cookie sending order template for this session.
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<Box<str>> = order.into_iter().map(|s| s.into()).collect();
        if !names.is_empty() {
            self.cookie_order = Some(names);
        }
        self
    }

    /// Choose how aggressively this session quarantines an origin after a
    /// QUIC handshake or H3 request failure.
    ///
    /// See [`BrokenQuicPolicy`] for the full menu — the most useful presets
    /// are [`BrokenQuicPolicy::Strict`] (default, Chrome-like persistence)
    /// and [`BrokenQuicPolicy::Resilient`] (recommended when running behind
    /// a transparent proxy such as mihomo / clash / sing-box, where 5-minute
    /// quarantine windows would silently keep H3 disabled long after the
    /// upstream actually recovered).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// use lkrequest::BrokenQuicPolicy;
    ///
    /// # let client = Client::builder().fingerprint(presets::chrome_146()).build();
    /// // Keep Chrome's H2 → alt-svc → H3 upgrade path, but recover from
    /// // transient QUIC failures within ~1s instead of being pinned to H2
    /// // for 5 minutes.
    /// let session = client
    ///     .session()
    ///     .broken_quic_policy(BrokenQuicPolicy::Resilient)
    ///     .build();
    /// ```
    pub fn broken_quic_policy(mut self, policy: BrokenQuicPolicy) -> Self {
        self.broken_quic_policy = Some(policy);
        self
    }

    /// Set the browsing context used to partition TLS and QUIC session tickets.
    ///
    /// The Client policy decides which dimensions become part of the cache key.
    /// Build a new Session when the top-level browsing context changes.
    pub fn network_partition_context(mut self, context: NetworkPartitionContext) -> Self {
        self.network_partition_context = Some(context);
        self
    }

    /// Build the [`Session`].
    ///
    /// If no TLS fingerprint was set on the `Client`, Chrome 144 defaults
    /// are used (TLS + H2 + header order).
    pub fn build(self) -> Session {
        let SessionBuilder {
            client,
            proxy,
            redirect_policy,
            https_only,
            hsts_policy,
            retry_policy,
            ech_config,
            middlewares,
            protocol_policy: protocol_policy_override,
            preferred_http_version,
            protocol_selection_policy,
            chrome_like_protocol_config,
            default_accept_encoding,
            max_connections_override,
            idle_timeout,
            header_order,
            h3_header_order,
            cookie_order,
            broken_quic_policy,
            network_partition_context,
        } = self;

        let preferred_http_version = preferred_http_version.unwrap_or(PreferredHttpVersion::Auto);
        let protocol_selection_policy =
            protocol_selection_policy.unwrap_or(ProtocolSelectionPolicy::Deterministic);
        let chrome_like_protocol_config =
            chrome_like_protocol_config.unwrap_or_else(ChromeLikeProtocolConfig::default);
        let protocol_policy = protocol_policy_override.unwrap_or_else(|| {
            let mut policy = client.protocol_policy().clone();
            apply_legacy_protocol_policy_overrides(
                &mut policy,
                preferred_http_version,
                protocol_selection_policy,
                chrome_like_protocol_config,
            );
            policy
        });
        let max_conn = max_connections_override
            .unwrap_or_else(|| client.resource_limits().max_connections_per_session);
        let mut pool = ConnectionPool::with_max_total(max_conn);
        if let Some(idle_timeout) = idle_timeout {
            pool.idle_timeout = idle_timeout;
        }
        // Per-session fingerprint materialization. When the client carries a
        // synthetic randomization policy, each session draws its own identity
        // from a fresh OS seed and presents a distinct (capability-safe)
        // fingerprint; the transport machinery stays shared inside the derived
        // client. Real-preset clients pass through unchanged.
        #[cfg(feature = "synthetic-fp")]
        let (client, session_store) = materialize_session_fingerprint(client);
        #[cfg(not(feature = "synthetic-fp"))]
        let session_store = client.inner.session_store.clone();
        let session_store = PartitionedSessionStore::wrap(
            session_store,
            client.inner.tls_session_cache_partition_policy,
            network_partition_context.as_ref(),
        );
        Session {
            inner: Arc::new(SessionInner {
                client,
                cookie_jar: ArcSwap::from_pointee(CookieStore::new()),
                pool: Mutex::new(pool),
                proxy,
                redirect_policy,
                https_only,
                hsts_policy: hsts_policy.unwrap_or_else(|| Arc::new(crate::hsts::NoHsts)),
                session_store,
                retry_policy,
                ech_config,
                middlewares,
                protocol_policy,
                preferred_http_version,
                protocol_selection_policy,
                chrome_like_protocol_config,
                default_accept_encoding,
                header_order,
                h3_header_order,
                cookie_order,
                alt_svc_cache: AltSvcCache::new(),
                broken_quic_tracker: broken_quic_policy
                    .map(|policy| BrokenQuicTracker::with_config(policy.resolve()))
                    .unwrap_or_else(BrokenQuicTracker::new),
                https_rr_handoff: Mutex::new(HttpsRrHandoff::default()),
                #[cfg(feature = "quic-h3")]
                quic_in_flight: Mutex::new(std::collections::HashMap::new()),
            }),
        }
    }
}

/// Materialize a session's wire fingerprint from the client's randomization
/// policy, returning the (possibly re-fingerprinted) client and the ticket
/// store the session should use.
///
/// A synthetic session also gets its **own** PSK/ticket cache: resuming another
/// identity's ticket would betray that two distinct fingerprints are the same
/// caller, so synthetic sessions never share the client-level cache. Real-preset
/// sessions keep sharing it (matching browser PSK-caching behavior).
#[cfg(feature = "synthetic-fp")]
fn materialize_session_fingerprint(client: Client) -> (Client, Arc<dyn SessionStore>) {
    use crate::randomize::{Layers, RandomizeMode};
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let mode = client.randomize().mode();
    let layers = match mode {
        RandomizeMode::Recombine(l) | RandomizeMode::Full(l) => l,
        // Off / ExtensionOrder: no per-session materialization.
        _ => {
            let store = client.inner.session_store.clone();
            return (client, store);
        }
    };

    let mut seed = [0u8; 32];
    // OS entropy. On the vanishingly rare RNG failure, fall through to the base
    // fingerprint rather than panicking inside session construction.
    if SystemRandom::new().fill(&mut seed).is_ok() {
        let floor = client.randomize().floor();
        let id = if matches!(mode, RandomizeMode::Full(_)) {
            crate::randomize::resolve_full_identity(seed, floor)
        } else {
            crate::randomize::resolve_recombine_identity(seed, floor)
        };
        let client = client.with_synthesized_fingerprint(id, layers);
        // Only isolate the PSK/ticket cache when a crypto-bearing layer (TLS or
        // QUIC) is synthesized; an H2-only synthetic identity keeps the real
        // TLS/QUIC, so sharing the client cache stays consistent.
        let store = if layers.intersects(Layers::TLS | Layers::QUIC) {
            Arc::new(InMemorySessionStore::new())
        } else {
            client.inner.session_store.clone()
        };
        return (client, store);
    }
    let store = client.inner.session_store.clone();
    (client, store)
}

/// Extract the server-supplied `ECHConfigList` from an ECH-rejection error.
///
/// Returns `None` for every other error, and for an ECH rejection that carried
/// no `retry_configs` — there is nothing to retry *with* in that case, and
/// redialing would repeat the same rejection.
fn ech_retry_configs<T>(result: &crate::error::Result<T>) -> Option<Vec<u8>> {
    match result {
        Err(crate::error::Error::Tls(lktls::error::TlsError::EchRejected { retry_configs })) => {
            retry_configs.clone()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // ECH configuration precedence (session > client > DNS HTTPS RR)
    // ====================================================================

    /// Resolver that records every host passed to `resolve` / `lookup_https`
    /// and answers HTTPS-RR queries with `https`. Tests use the recorded hosts
    /// to assert both that a remote-DNS route performs **no** local lookup for
    /// the target (DNS leak) and that one request never queries twice.
    #[derive(Clone, Default)]
    struct RecordingDns {
        https: Option<HttpsRecord>,
        resolve_calls: Arc<std::sync::Mutex<Vec<String>>>,
        https_calls: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingDns {
        fn with_ech(ech: Vec<u8>) -> Self {
            Self {
                https: Some(HttpsRecord {
                    ech_config_list: Some(ech),
                    ..HttpsRecord::default()
                }),
                ..Self::default()
            }
        }

        /// Snapshot the recorded HTTPS-RR hosts. Callers must snapshot *before*
        /// asserting: `assert!` builds its message only on failure, and
        /// re-locking this non-reentrant mutex there — while the condition's
        /// guard is still alive to end-of-statement — deadlocks, so the test
        /// would hang instead of reporting the leak it exists to catch.
        /// Every caller is an H3 test, so this is dead code without the feature.
        #[cfg(feature = "quic-h3")]
        fn https_calls(&self) -> Vec<String> {
            self.https_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::dns::DnsResolver for RecordingDns {
        async fn resolve(
            &self,
            host: &str,
            port: u16,
        ) -> std::io::Result<Vec<std::net::SocketAddr>> {
            self.resolve_calls.lock().unwrap().push(host.to_string());
            Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
        }

        async fn lookup_https(&self, host: &str) -> std::io::Result<Option<HttpsRecord>> {
            self.https_calls.lock().unwrap().push(host.to_string());
            Ok(self.https.clone())
        }
    }

    fn ech_test_client(resolver: RecordingDns) -> Client {
        let builder = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .dns_resolver(Arc::new(resolver));
        #[cfg(feature = "quic-h3")]
        let builder = builder.quic_profile(lkh3::chrome_quic());
        builder.build()
    }

    const DNS_ECH: [u8; 4] = [0xFE, 0x0D, 0x00, 0xDD];
    const CLIENT_ECH: [u8; 4] = [0xFE, 0x0D, 0x00, 0xCC];
    const SESSION_ECH: [u8; 4] = [0xFE, 0x0D, 0x00, 0x55];

    /// Both transports resolve ECH through this one helper, so its precedence
    /// *is* the precedence the TCP and H3 handshakes get: an explicit
    /// session-level override first, then the client-level one, then whatever
    /// the DNS HTTPS RR advertises.
    #[tokio::test]
    async fn resolve_ech_config_prefers_session_then_client_then_dns() {
        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());

        let dns_only = ech_test_client(resolver.clone()).session().build();
        assert_eq!(
            dns_only
                .resolve_ech_config("example.com", false, DiscoveredHttpsRr::Unqueried)
                .await,
            Some(DNS_ECH.to_vec()),
            "with no override, the HTTPS RR supplies the ECH config",
        );

        let client_level = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .dns_resolver(Arc::new(resolver.clone()))
            .ech_config(CLIENT_ECH.to_vec())
            .build()
            .session()
            .build();
        assert_eq!(
            client_level
                .resolve_ech_config("example.com", false, DiscoveredHttpsRr::Unqueried)
                .await,
            Some(CLIENT_ECH.to_vec()),
            "a client-level ECH config outranks the DNS record",
        );

        let session_level = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .dns_resolver(Arc::new(resolver.clone()))
            .ech_config(CLIENT_ECH.to_vec())
            .build()
            .session()
            .ech_config(SESSION_ECH.to_vec())
            .build();
        assert_eq!(
            session_level
                .resolve_ech_config("example.com", false, DiscoveredHttpsRr::Unqueried)
                .await,
            Some(SESSION_ECH.to_vec()),
            "a session-level override outranks the client-level one",
        );

        // The DNS level — and only that level — is gated on local resolution.
        assert_eq!(
            dns_only
                .resolve_ech_config("example.com", true, DiscoveredHttpsRr::Unqueried)
                .await,
            None,
            "a remote-DNS route must not pick up a DNS-discovered ECH config",
        );
        assert_eq!(
            session_level
                .resolve_ech_config("example.com", true, DiscoveredHttpsRr::Unqueried)
                .await,
            Some(SESSION_ECH.to_vec()),
            "an explicit override still applies on a remote-DNS route",
        );
    }

    /// The H3 handshake used to read `client.ech_config()` and nothing else, so
    /// a session-level override was silently ignored and a DNS-discovered ECH
    /// config never reached QUIC at all. It must now follow the same route as
    /// the TCP path: park nothing, leak nothing, and actually look the record up
    /// when this request has not already.
    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn h3_connect_resolves_ech_the_same_way_the_tcp_path_does() {
        // Port 0 is rejected by quinn before a packet is sent, so the connect
        // fails immediately — after the ECH resolution under test.
        async fn h3_connect(session: &Session, proxy: Option<&crate::proxy::ProxyConfig>) {
            let result = session
                .establish_h3_connection_with_0rtt("example.com", 0, None, None, proxy, false)
                .await;
            assert!(
                result.is_err(),
                "dialing port 0 cannot succeed; this test only exercises the setup before it",
            );
        }

        // Direct route, nothing parked: the H3 path must run the (gated) lookup
        // itself, exactly as `build_tls_connector` does.
        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());
        let session = ech_test_client(resolver.clone()).session().build();
        h3_connect(&session, None).await;
        assert_eq!(
            resolver.https_calls(),
            ["example.com"],
            "the H3 path must discover ECH from DNS on a direct route",
        );

        // Remote-DNS route: the proxy resolves the target, so a local HTTPS-RR
        // query here would leak the target hostname out-of-band from the proxy.
        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());
        let session = ech_test_client(resolver.clone()).session().build();
        let socks5h = crate::proxy::ProxyConfig::parse("socks5h://proxy.example.com:1080")
            .expect("test proxy URL parses");
        h3_connect(&session, Some(&socks5h)).await;
        let https_calls = resolver.https_calls();
        assert!(
            https_calls.is_empty(),
            "remote-DNS routes must not perform a local HTTPS-RR lookup (DNS leak); got \
             {https_calls:?}",
        );

        // An explicit override short-circuits the DNS level entirely.
        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());
        let session = ech_test_client(resolver.clone())
            .session()
            .ech_config(SESSION_ECH.to_vec())
            .build();
        h3_connect(&session, None).await;
        let https_calls = resolver.https_calls();
        assert!(
            https_calls.is_empty(),
            "a session-level ECH override needs no DNS lookup; got {https_calls:?}",
        );
    }

    /// The precedence the QUIC crypto configuration actually ends up with.
    /// Reading it off the built config is what pins the H3 path to the same
    /// order as the TCP path: before this, `client.ech_config()` was the only
    /// source it consulted, so both the session override and the DNS record
    /// below were dropped on the floor.
    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn h3_crypto_applies_the_session_client_dns_ech_precedence() {
        async fn h3_ech(session: &Session, is_remote_dns: bool) -> Option<Vec<u8>> {
            session
                .build_h3_crypto(
                    lktls::profile::presets::chrome_146_quic(),
                    None,
                    "example.com",
                    443,
                    is_remote_dns,
                )
                .await
                .ech_config_list()
                .map(<[u8]>::to_vec)
        }

        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());

        let dns_only = ech_test_client(resolver.clone()).session().build();
        assert_eq!(
            h3_ech(&dns_only, false).await,
            Some(DNS_ECH.to_vec()),
            "the QUIC handshake must pick up a DNS-discovered ECH config",
        );

        let client_level = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .dns_resolver(Arc::new(resolver.clone()))
            .quic_profile(lkh3::chrome_quic())
            .ech_config(CLIENT_ECH.to_vec())
            .build()
            .session()
            .build();
        assert_eq!(
            h3_ech(&client_level, false).await,
            Some(CLIENT_ECH.to_vec()),
            "a client-level ECH config outranks the DNS record on QUIC too",
        );

        let session_level = client_level
            .inner
            .client
            .session()
            .ech_config(SESSION_ECH.to_vec())
            .build();
        assert_eq!(
            h3_ech(&session_level, false).await,
            Some(SESSION_ECH.to_vec()),
            "a session-level override must reach the QUIC handshake",
        );
        assert_eq!(
            h3_ech(&session_level, true).await,
            Some(SESSION_ECH.to_vec()),
            "an explicit override still applies on a remote-DNS route",
        );
        assert_eq!(
            h3_ech(&dns_only, true).await,
            None,
            "but DNS discovery does not run there — that would leak the target",
        );
    }

    /// One request, one HTTPS-RR query: the H3 handshake reuses the record
    /// protocol discovery parked for it — and leaves it parked, because a QUIC
    /// failure falls back to TCP on the same request and `establish_connection`
    /// still has to find it there.
    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn h3_connect_reuses_the_parked_https_rr_without_consuming_it() {
        let resolver = RecordingDns::with_ech(DNS_ECH.to_vec());
        let session = ech_test_client(resolver.clone()).session().build();
        session.publish_discovered_https_rr(
            "example.com",
            Some(HttpsRecord {
                ech_config_list: Some(DNS_ECH.to_vec()),
                ..HttpsRecord::default()
            }),
        );

        let result = session
            .establish_h3_connection_with_0rtt("example.com", 0, None, None, None, false)
            .await;
        assert!(result.is_err(), "dialing port 0 cannot succeed");

        let https_calls = resolver.https_calls();
        assert!(
            https_calls.is_empty(),
            "the parked record must be reused, not re-queried; got {https_calls:?}",
        );
        assert!(
            session.take_discovered_https_rr("example.com").is_some(),
            "the hand-off must survive for this request's TCP fallback to claim",
        );
    }

    // ====================================================================
    // DNS HTTPS (SVCB) record hand-off
    // ====================================================================

    /// The hand-off must behave like a hand-off and not like a DNS cache: a
    /// parked record is claimable exactly once, and only briefly — otherwise a
    /// record parked by a request that never reached a TLS handshake (an
    /// all-H3 origin, say) could resurface much later with a stale ECH key.
    #[test]
    fn https_rr_handoff_is_single_use_and_expires() {
        let mut handoff = HttpsRrHandoff::default();
        let now = std::time::Instant::now();

        handoff.publish("example.com", Some(HttpsRecord::default()), now);
        assert!(
            handoff.claim("example.com", now).is_some(),
            "a freshly parked record must be claimable",
        );
        assert!(
            handoff.claim("example.com", now).is_none(),
            "claiming a parked record must consume it",
        );

        // A miss is worth parking too — it spares the second query.
        handoff.publish("example.com", None, now);
        assert_eq!(
            handoff.claim("example.com", now),
            Some(None),
            "a parked lookup miss must be distinguishable from nothing parked",
        );

        handoff.publish("example.com", Some(HttpsRecord::default()), now);
        assert!(
            handoff
                .claim("example.com", now + HTTPS_RR_HANDOFF_TTL)
                .is_none(),
            "an expired entry must not be claimable",
        );

        assert!(
            handoff.claim("other.example", now).is_none(),
            "a host nobody parked must report nothing",
        );
    }

    /// A session that keeps discovering origins without ever claiming (all-H3
    /// traffic) must not grow the hand-off map without bound.
    #[test]
    fn https_rr_handoff_is_capacity_bounded() {
        let mut handoff = HttpsRrHandoff::default();
        let now = std::time::Instant::now();

        for i in 0..(HTTPS_RR_HANDOFF_MAX_ENTRIES * 2) {
            handoff.publish(&format!("host{i}.example"), None, now);
        }

        assert!(
            handoff.entries.len() <= HTTPS_RR_HANDOFF_MAX_ENTRIES,
            "hand-off map grew past its bound: {} entries",
            handoff.entries.len(),
        );
    }

    // ====================================================================
    // RFC 6265bis origin-server storage rules — §5.6 step 15 (`Secure` needs
    // a secure channel) and §4.1.3 (`__Secure-` / `__Host-` name prefixes)
    // ====================================================================

    fn storable(set_cookie: &str, url: &str) -> bool {
        let raw = cookie_store::RawCookie::parse(set_cookie.to_string())
            .expect("test Set-Cookie header parses");
        let parsed = Url::parse(url).expect("test URL parses");
        origin_cookie_allows_storage(&raw, &parsed)
    }

    /// §5.6 step 15: a `Secure` cookie that did not arrive over a secure
    /// channel is ignored entirely — no name prefix required.
    #[test]
    fn secure_attribute_over_plain_http_is_ignored() {
        assert!(
            !storable("sid=1; Secure", "http://example.com/"),
            "an ordinary Secure cookie over http:// must be ignored"
        );
        assert!(
            !storable(
                "sid=1; Secure; Path=/app; Domain=example.com",
                "http://example.com/app"
            ),
            "attributes do not rescue a Secure cookie set over http://"
        );
        assert!(
            !storable("sid=1; secure", "http://example.com/"),
            "the Secure attribute is matched case-insensitively"
        );
        assert!(
            !storable("sid=1; Secure", "ws://example.com/"),
            "ws:// is not a secure channel either"
        );
    }

    /// The counter-cases: the §5.6 rule must not reject cookies a browser
    /// would keep.
    #[test]
    fn secure_channel_rule_leaves_conforming_cookies_alone() {
        assert!(
            storable("sid=1; Secure", "https://example.com/"),
            "a Secure cookie over https must still be stored"
        );
        assert!(
            storable("sid=1; Secure", "wss://example.com/"),
            "wss counts as a secure channel"
        );
        assert!(
            storable("sid=1", "http://example.com/"),
            "a cookie without Secure is unaffected over http"
        );
        assert!(
            storable(
                "sid=1; Path=/app; Domain=example.com; HttpOnly",
                "http://example.com/app"
            ),
            "non-Secure attributes are unaffected over http"
        );
    }

    /// §4.1.3.2: `__Host-` demands `Secure`, a secure channel, no `Domain`,
    /// and `Path=/` exactly.
    #[test]
    fn host_prefix_requires_secure_no_domain_and_root_path() {
        assert!(
            storable("__Host-a=1; Secure; Path=/", "https://example.com/"),
            "canonical __Host- cookie must be storable"
        );
        assert!(
            !storable(
                "__Host-a=1; Secure; Path=/; Domain=example.com",
                "https://example.com/"
            ),
            "__Host- with a Domain attribute must be ignored"
        );
        assert!(
            !storable("__Host-a=1; Secure; Path=/sub", "https://example.com/sub"),
            "__Host- with a non-root Path must be ignored"
        );
        assert!(
            !storable("__Host-a=1; Secure", "https://example.com/"),
            "__Host- without an explicit Path=/ must be ignored"
        );
        assert!(
            !storable("__Host-a=1; Path=/", "https://example.com/"),
            "__Host- without Secure must be ignored"
        );
        assert!(
            !storable("__Host-a=1; Secure; Path=/", "http://example.com/"),
            "__Host- over a non-secure channel must be ignored"
        );
    }

    /// §4.1.3.1: `__Secure-` demands `Secure` plus a secure channel, and
    /// nothing else.
    #[test]
    fn secure_prefix_requires_secure_attribute_and_secure_channel() {
        assert!(
            storable("__Secure-a=1; Secure", "https://example.com/"),
            "canonical __Secure- cookie must be storable"
        );
        assert!(
            storable(
                "__Secure-a=1; Secure; Domain=example.com; Path=/deep",
                "https://example.com/deep"
            ),
            "__Secure- places no constraint on Domain/Path"
        );
        assert!(
            !storable("__Secure-a=1", "https://example.com/"),
            "__Secure- without the Secure attribute must be ignored"
        );
        assert!(
            !storable("__Secure-a=1; Secure", "http://example.com/"),
            "__Secure- over a non-secure channel must be ignored"
        );
    }

    /// The prefixes are matched ASCII case-insensitively, so casing tricks
    /// cannot smuggle a cookie past the rule.
    #[test]
    fn prefix_matching_is_ascii_case_insensitive() {
        assert!(
            !storable(
                "__hOsT-a=1; Secure; Path=/; Domain=example.com",
                "https://example.com/"
            ),
            "__Host- must be recognised regardless of case"
        );
        assert!(
            !storable("__SECURE-a=1", "https://example.com/"),
            "__Secure- must be recognised regardless of case"
        );
        assert!(
            storable("__hOsT-a=1; Secure; Path=/", "https://example.com/"),
            "a conforming __Host- cookie is still accepted in any casing"
        );
    }

    /// Ordinary names — including ones that merely resemble a prefix, and
    /// non-ASCII names (which must not panic on byte slicing) — are untouched.
    #[test]
    fn ordinary_cookie_names_are_unaffected_by_prefix_rules() {
        assert!(storable("sid=1", "http://example.com/"));
        assert!(storable(
            "sid=1; Domain=example.com; Path=/x",
            "http://example.com/x"
        ));
        assert!(
            storable("__Hostile=1", "http://example.com/"),
            "only the exact `__Host-` prefix is special"
        );
        assert!(
            storable("__Secure=1", "http://example.com/"),
            "`__Secure` without the trailing hyphen is an ordinary name"
        );
        assert!(
            storable("__=1", "http://example.com/"),
            "a name shorter than the prefix must not panic"
        );
        assert!(
            storable("__Höst-a=1", "http://example.com/"),
            "a non-ASCII name must not panic on the prefix comparison"
        );
    }

    /// `wss://` is a secure channel too (cookies are shared with `https`).
    #[test]
    fn websocket_secure_scheme_counts_as_a_secure_channel() {
        assert!(storable("__Secure-a=1; Secure", "wss://example.com/"));
        assert!(!storable("__Secure-a=1; Secure", "ws://example.com/"));
    }

    /// Only an ECH rejection that actually carried `retry_configs` is worth
    /// redialing for; everything else must surface unchanged.
    #[test]
    fn ech_retry_configs_only_fires_on_a_rejection_carrying_configs() {
        let with_configs: crate::error::Result<()> = Err(crate::error::Error::Tls(
            lktls::error::TlsError::EchRejected {
                retry_configs: Some(vec![1, 2, 3]),
            },
        ));
        assert_eq!(ech_retry_configs(&with_configs), Some(vec![1, 2, 3]));

        // A rejection with nothing to retry with: redialing would just repeat it.
        let without_configs: crate::error::Result<()> = Err(crate::error::Error::Tls(
            lktls::error::TlsError::EchRejected {
                retry_configs: None,
            },
        ));
        assert_eq!(ech_retry_configs(&without_configs), None);

        // Any other TLS failure is not an ECH rejection.
        let other: crate::error::Result<()> = Err(crate::error::Error::Tls(
            lktls::error::TlsError::HandshakeFailure("nope".into()),
        ));
        assert_eq!(ech_retry_configs(&other), None);

        let ok: crate::error::Result<()> = Ok(());
        assert_eq!(ech_retry_configs(&ok), None);
    }

    fn test_client() -> Client {
        Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build()
    }

    fn test_session() -> Session {
        test_client().session().build()
    }

    // ====================================================================
    // AcceptEncoding — browser encoding negotiation
    // ====================================================================

    #[test]
    fn session_builder_defaults_to_strict_broken_quic_policy() {
        let session = test_client().session().build();
        let entry = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&entry);
        assert!(
            tracker.is_broken(&entry),
            "default policy should be Strict — origin must stay quarantined"
        );
    }

    #[test]
    fn session_builder_resilient_policy_recovers_within_a_few_seconds() {
        use crate::alt_svc::BrokenQuicPolicy;
        use std::thread::sleep;
        use std::time::Duration;

        let session = test_client()
            .session()
            .broken_quic_policy(BrokenQuicPolicy::Resilient)
            .build();
        let origin = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&origin);
        assert!(
            tracker.is_broken(&origin),
            "Resilient still quarantines briefly — should be true immediately after mark_broken"
        );
        sleep(Duration::from_millis(1100));
        assert!(
            !tracker.is_broken(&origin),
            "Resilient policy must let the origin recover after ~1s"
        );
    }

    #[test]
    fn session_builder_disabled_policy_never_quarantines() {
        use crate::alt_svc::BrokenQuicPolicy;
        let session = test_client()
            .session()
            .broken_quic_policy(BrokenQuicPolicy::Disabled)
            .build();
        let origin = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&origin);
        assert!(
            !tracker.is_broken(&origin),
            "Disabled policy must report origin as healthy even after mark_broken"
        );
    }

    #[test]
    fn early_data_gate_matches_chrome_idempotency_rules() {
        assert!(can_send_early_data(
            &http::Method::GET,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::HEAD,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::OPTIONS,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::TRACE,
            Idempotency::Default
        ));
        assert!(!can_send_early_data(
            &http::Method::POST,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::POST,
            Idempotency::Idempotent
        ));
        assert!(!can_send_early_data(
            &http::Method::GET,
            Idempotency::NotIdempotent
        ));
    }

    #[test]
    fn gzip_only_header() {
        assert_eq!(AcceptEncoding::GZIP.to_header_value(), "gzip");
    }

    #[test]
    fn brotli_only_header() {
        assert_eq!(AcceptEncoding::BR.to_header_value(), "br");
    }

    #[test]
    fn chrome_default_advertises_all_encodings() {
        let hdr = AcceptEncoding::CHROME_DEFAULT.to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("br"));
        assert!(hdr.contains("deflate"));
        assert!(hdr.contains("zstd"));
    }

    #[test]
    fn safari_default_excludes_zstd() {
        let hdr = AcceptEncoding::SAFARI_DEFAULT.to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("br"));
        assert!(!hdr.contains("zstd"));
    }

    #[test]
    fn combining_two_encodings() {
        let hdr = (AcceptEncoding::GZIP | AcceptEncoding::ZSTD).to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("zstd"));
        assert!(!hdr.contains("br"));
    }

    // ====================================================================
    // Cookie jar — simulating a browser user
    // ====================================================================

    #[test]
    fn login_sets_session_cookie() {
        let session = test_session();
        session.set_cookie("https://app.example.com", "session_id", "abc123");

        assert_eq!(
            session.get_cookie("https://app.example.com", "session_id"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn cookies_scoped_by_domain() {
        let session = test_session();
        session.set_cookie("https://a.example.com", "token", "aaa");
        session.set_cookie("https://b.example.com", "token", "bbb");

        assert_eq!(
            session.get_cookie("https://a.example.com", "token"),
            Some("aaa".to_string())
        );
        assert_eq!(
            session.get_cookie("https://b.example.com", "token"),
            Some("bbb".to_string())
        );
    }

    #[test]
    fn same_name_different_paths() {
        let session = test_session();
        session.set_cookie_with_attrs(
            "https://example.com",
            "token",
            "root_val",
            Some("/"),
            None,
            false,
            false,
        );
        session.set_cookie_with_attrs(
            "https://example.com",
            "token",
            "api_val",
            Some("/api"),
            None,
            false,
            false,
        );

        let values = session.get_cookie_values("https://example.com/api/users", "token");
        assert!(values.len() >= 2);
        assert!(values.contains(&"api_val".to_string()));
        assert!(values.contains(&"root_val".to_string()));
    }

    #[test]
    fn set_cookie_raw_from_server_header() {
        let session = test_session();
        session.set_cookie_raw(
            "https://example.com",
            "tracking=xyz789; Path=/; Domain=example.com; Secure; HttpOnly",
        );
        assert_eq!(
            session.get_cookie("https://example.com", "tracking"),
            Some("xyz789".to_string())
        );
    }

    #[test]
    fn cookie_header_format() {
        let session = test_session();
        session.set_cookie("https://example.com", "a", "1");
        session.set_cookie("https://example.com", "b", "2");

        let header = session.cookie_header("https://example.com").unwrap();
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
        assert!(header.contains("; "));
    }

    #[test]
    fn no_cookies_returns_none() {
        let session = test_session();
        assert!(session.cookie_header("https://example.com").is_none());
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn logout_clears_all_cookies() {
        let session = test_session();
        session.set_cookie("https://example.com", "a", "1");
        session.set_cookie("https://example.com", "b", "2");
        assert!(!session.get_cookies("https://example.com").is_empty());

        session.clear_cookies();
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn remove_specific_cookie() {
        let session = test_session();
        session.set_cookie("https://example.com", "keep", "yes");
        session.set_cookie("https://example.com", "remove_me", "bye");

        session.remove_cookie("https://example.com", "remove_me");

        assert!(session.get_cookie("https://example.com", "keep").is_some());
        assert!(session
            .get_cookie("https://example.com", "remove_me")
            .is_none());
    }

    #[test]
    fn invalid_url_is_warned_and_ignored() {
        let session = test_session();
        session.set_cookie("not-a-url", "k", "v");
        assert!(session.get_cookies("not-a-url").is_empty());
        assert!(session.get_cookie("not-a-url", "k").is_none());
    }

    #[test]
    fn set_cookie_with_attrs_invalid_url_no_panic() {
        let session = test_session();
        session.set_cookie_with_attrs("not-a-url", "k", "v", Some("/"), None, false, false);
        assert!(session.get_cookies("not-a-url").is_empty());
    }

    #[test]
    fn set_cookie_raw_invalid_url_no_panic() {
        let session = test_session();
        session.set_cookie_raw("not-a-url", "k=v; Path=/");
        assert!(session.get_cookies("not-a-url").is_empty());
    }

    #[test]
    fn set_cookie_raw_invalid_header_no_panic() {
        let session = test_session();
        session.set_cookie_raw("https://example.com", "");
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn remove_cookie_invalid_url_no_panic() {
        let session = test_session();
        session.remove_cookie("not-a-url", "k");
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn cookie_with_secure_and_httponly_attrs() {
        let session = test_session();
        session.set_cookie_with_attrs(
            "https://secure.example.com",
            "secret",
            "val",
            Some("/"),
            Some("secure.example.com"),
            true,
            true,
        );
        assert_eq!(
            session.get_cookie("https://secure.example.com/path", "secret"),
            Some("val".to_string())
        );
    }

    // ====================================================================
    // SessionBuilder — configuring a session for different use cases
    // ====================================================================

    #[test]
    fn build_session_with_defaults() {
        let session = test_session();
        assert!(session.inner.proxy.is_none());
        assert_eq!(session.inner.redirect_policy, RedirectPolicy::default());
        assert!(session.inner.ech_config.is_none());
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Auto
        );
        assert_eq!(
            session.inner.protocol_selection_policy,
            ProtocolSelectionPolicy::Deterministic
        );
        assert_eq!(
            session.inner.chrome_like_protocol_config,
            ChromeLikeProtocolConfig::default()
        );
        assert_eq!(
            session.protocol_policy(),
            &ProtocolPolicy::crawler_throughput()
        );
    }

    #[test]
    fn build_session_inherits_client_protocol_policy() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::h3_strict())
            .build();
        let session = client.session().build();
        assert_eq!(session.protocol_policy(), &ProtocolPolicy::h3_strict());
    }

    #[test]
    fn build_session_protocol_policy_overrides_client_default() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(ProtocolPolicy::chrome_standard())
            .build();
        assert_eq!(
            session.protocol_policy(),
            &ProtocolPolicy::chrome_standard()
        );
    }

    #[test]
    fn build_session_http_intent_override_normalizes_conflicting_axes() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::chrome_standard())
            .build();
        let session = client.session().http_intent(HttpIntent::H2Only).build();
        assert_eq!(session.protocol_policy().intent, HttpIntent::H2Only);
        assert_eq!(
            session.protocol_policy().fallback,
            FallbackPolicy::NoFallback
        );
        assert_eq!(
            session.protocol_policy().upgrade,
            crate::protocol::UpgradePolicy::Off
        );
    }

    #[test]
    fn build_session_for_scraping_with_proxy() {
        let client = test_client();
        let session = client
            .session()
            .proxy("http://proxy.example.com:8080")
            .max_redirects(3)
            .build();

        assert!(session.inner.proxy.is_some());
        assert_eq!(session.inner.redirect_policy, RedirectPolicy::Follow(3));
    }

    #[test]
    fn build_session_forced_http1() {
        let client = test_client();
        let session = client.session().http1_only().build();
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Http1Only
        );
    }

    #[test]
    fn build_session_forced_http2() {
        let client = test_client();
        let session = client.session().http2_only().build();
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Http2Only
        );
    }

    #[test]
    fn build_session_with_encoding_preference() {
        let client = test_client();
        let session = client
            .session()
            .default_accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
            .build();
        assert_eq!(
            session.inner.default_accept_encoding,
            Some(AcceptEncoding::GZIP | AcceptEncoding::BR)
        );
    }

    #[test]
    fn build_session_with_chrome_like_protocol_policy() {
        let client = test_client();
        let session = client
            .session()
            .protocol_selection_policy(ProtocolSelectionPolicy::ChromeLike)
            .build();
        assert_eq!(
            session.inner.protocol_selection_policy,
            ProtocolSelectionPolicy::ChromeLike
        );
    }

    #[test]
    fn build_session_with_custom_chrome_like_protocol_config() {
        let client = test_client();
        let config = ChromeLikeProtocolConfig {
            tcp_main_job_delay: std::time::Duration::from_secs(1),
            keep_quic_probe_after_tcp_win: false,
            keep_tcp_probe_after_quic_win: true,
        };
        let session = client.session().chrome_like_protocol_config(config).build();
        assert_eq!(session.inner.chrome_like_protocol_config, config);
    }

    #[test]
    fn build_session_with_ech_config() {
        let client = test_client();
        let ech_data = vec![0xFE, 0x0D, 0x00, 0x10];
        let session = client.session().ech_config(ech_data.clone()).build();
        assert_eq!(session.inner.ech_config, Some(ech_data));
    }

    #[test]
    fn build_session_with_custom_connection_limit() {
        let client = test_client();
        let session = client.session().max_connections(5).build();
        let lock = session.inner.pool.try_lock().unwrap();
        assert_eq!(lock.max_total, 5);
    }

    #[test]
    fn http1_only_session_has_no_default_connection_limit() {
        let client = test_client();
        let session = client.session().http1_only().build();
        let lock = session.inner.pool.try_lock().unwrap();
        assert_eq!(lock.max_total, usize::MAX);
    }

    #[test]
    fn invalid_proxy_url_is_logged_but_not_fatal() {
        let client = test_client();
        let session = client.session().proxy("not-a-valid-proxy").build();
        assert!(session.inner.proxy.is_none());
    }

    #[test]
    fn session_is_clone_and_shares_state() {
        let session = test_session();
        session.set_cookie("https://example.com", "shared", "yes");

        let clone = session.clone();
        assert_eq!(
            clone.get_cookie("https://example.com", "shared"),
            Some("yes".to_string())
        );

        clone.set_cookie("https://example.com", "from_clone", "val");
        assert_eq!(
            session.get_cookie("https://example.com", "from_clone"),
            Some("val".to_string())
        );
    }

    #[test]
    fn client_accessible_from_session() {
        let session = test_session();
        let client = session.client();
        assert!(!client.tls_profile().cipher_suites.is_empty());
    }

    // ====================================================================
    // QUIC transport-parameter per-connection randomization (quic-h3)
    //
    // Wire-fidelity guards for the per-connection shuffle + GREASE
    // randomization that `establish_quic_connection` applies when
    // `shuffle_transport_parameters` is set. These run the real RNG-backed
    // functions offline (no network): structural invariants hold on every
    // iteration; the uniformity sanity check holds statistically with an
    // astronomically small false-failure probability. The offline
    // `fingerprint_regression` gate cannot see this path (it compares the
    // static profile), so these are its on-host counterpart.
    // ====================================================================
    #[cfg(feature = "quic-h3")]
    mod quic_tp_randomization {
        use super::*;

        /// Transport parameters Quinn encodes itself. An *extra* TP carrying one
        /// of these ids is rejected by `extra_transport_parameters` with
        /// `LocallyEncoded`, failing connection setup. Kept in sync with
        /// `deps/quinn/quinn-proto/src/config.rs::is_locally_encoded_transport_parameter`.
        const LOCALLY_ENCODED: &[u64] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x20, 0xb6, 0x2ab2, 0xff04de1a,
        ];

        fn vi(v: u64) -> quinn::VarInt {
            quinn::VarInt::from_u64(v).unwrap()
        }

        // version_information value from chrome_146_quic:
        // chosen(0x00000001) | available[GREASE(0x9a9aca7a), v1(0x00000001)].
        fn version_info_value() -> Vec<u8> {
            vec![
                0x00, 0x00, 0x00, 0x01, 0x9a, 0x9a, 0xca, 0x7a, 0x00, 0x00, 0x00, 0x01,
            ]
        }

        #[test]
        fn grease_id_is_reserved_pattern_8byte_and_never_locally_encoded() {
            // Boundary + adversarial inputs, including the value (5) that the old
            // `27 + 31*k` generator mapped to 0xb6, a Quinn-local TP.
            let samples = [
                0u32,
                1,
                2,
                5,
                31,
                1000,
                u32::MAX / 2,
                u32::MAX - 1,
                u32::MAX,
            ];
            for &r in &samples {
                let id = grease_reserved_tp_id(r).into_inner();
                assert_eq!(
                    (id - 27) % 31,
                    0,
                    "id {id:#x} must be reserved-pattern 31*N+27"
                );
                assert!(
                    id >= (1 << 30),
                    "id {id:#x} must encode as an 8-byte varint (>= 2^30)"
                );
                assert!(
                    id < (1u64 << 62),
                    "id {id:#x} must fit a QUIC varint (< 2^62)"
                );
                assert!(
                    !LOCALLY_ENCODED.contains(&id),
                    "id {id:#x} collides with a Quinn-local TP (would be rejected as LocallyEncoded)"
                );
            }
        }

        #[test]
        fn grease_id_old_collision_input_is_now_safe() {
            // Regression: `27 + 31*5 == 0xb6` (a Quinn-local TP) in the old
            // generator. The remapped generator must never produce it.
            assert_ne!(grease_reserved_tp_id(5).into_inner(), 0xb6);
        }

        #[test]
        fn randomize_rewrites_grease_id_in_extra_and_order_consistently() {
            let grease = vi(0x17af394a4ef8da0a); // chrome_146_quic captured reserved GREASE
            for _ in 0..2_000 {
                let mut extra = vec![
                    (vi(0x11), version_info_value()),
                    (grease, Vec::new()),
                    (vi(0x3127), vec![0x80, 0x09, 0xdf, 0x94]), // google_initial_rtt
                ];
                let mut order = vec![vi(0x03), vi(0x11), grease, vi(0x3127), vi(0x07)];
                randomize_quic_grease_params(&mut extra, &mut order);

                let new_id = extra[1].0;
                assert_ne!(new_id, grease, "GREASE id must be rerandomized");
                assert!(
                    !LOCALLY_ENCODED.contains(&new_id.into_inner()),
                    "rerandomized GREASE id must never be Quinn-local"
                );
                // The order list's reference must be patched to the new id, with
                // no stale reference left (else the wire order is inconsistent).
                assert!(
                    order.contains(&new_id),
                    "order must reference the new GREASE id"
                );
                assert!(
                    !order.contains(&grease),
                    "order must drop the stale GREASE id"
                );
                // GREASE value is rewritten to a non-empty, bounded-length blob.
                assert!(
                    (1..=16).contains(&extra[1].1.len()),
                    "GREASE value length {} out of expected 1..=16 \
                     (revisit if the capture shows Chrome sends an empty value)",
                    extra[1].1.len()
                );
                // google_initial_rtt (0x3127) is NOT a GREASE param — untouched.
                assert_eq!(extra[2].0, vi(0x3127));
                assert_eq!(extra[2].1, vec![0x80, 0x09, 0xdf, 0x94]);
            }
        }

        #[test]
        fn randomize_preserves_captured_grease_value_length() {
            let grease = vi(0x17af394a4ef8da0a);
            for _ in 0..100 {
                let mut extra = vec![(grease, vec![0])];
                let mut order = vec![grease];
                randomize_quic_grease_params(&mut extra, &mut order);
                assert_eq!(extra[0].1.len(), 1);
                assert_ne!(extra[0].0, grease);
                assert_eq!(order, vec![extra[0].0]);
            }
        }

        #[test]
        fn randomize_only_touches_grease_version_slot_of_version_information() {
            for _ in 0..2_000 {
                let mut extra = vec![(vi(0x11), version_info_value())];
                let mut order = vec![vi(0x11)];
                randomize_quic_grease_params(&mut extra, &mut order);
                let v = &extra[0].1;
                assert_eq!(v.len(), 12, "length unchanged");
                assert_eq!(
                    &v[0..4],
                    &[0, 0, 0, 1],
                    "chosen version (bytes 0..4) unchanged"
                );
                assert_eq!(
                    &v[8..12],
                    &[0, 0, 0, 1],
                    "trailing real version (bytes 8..) unchanged"
                );
                for (i, b) in v[4..8].iter().enumerate() {
                    assert_eq!(
                        b & 0x0f,
                        0x0a,
                        "GREASE version byte {i} must match 0x?a pattern"
                    );
                }
            }
        }

        #[test]
        fn shuffle_is_always_a_permutation() {
            let base: Vec<quinn::VarInt> = [0x03u64, 0x11, 0x09, 0x08, 0x20, 0x01, 0x06]
                .iter()
                .map(|&v| vi(v))
                .collect();
            for _ in 0..5_000 {
                let mut order = base.clone();
                shuffle_transport_parameter_order(&mut order);
                let mut got: Vec<u64> = order.iter().map(|v| v.into_inner()).collect();
                let mut want: Vec<u64> = base.iter().map(|v| v.into_inner()).collect();
                got.sort_unstable();
                want.sort_unstable();
                assert_eq!(got, want, "shuffle must preserve the exact multiset of ids");
            }
        }

        #[test]
        fn shuffle_is_identity_for_trivial_lengths() {
            let mut empty: Vec<quinn::VarInt> = vec![];
            shuffle_transport_parameter_order(&mut empty);
            assert!(empty.is_empty());

            let mut one = vec![vi(0x03)];
            shuffle_transport_parameter_order(&mut one);
            assert_eq!(one, vec![vi(0x03)]);
        }

        #[test]
        fn shuffle_reaches_every_position_for_every_element() {
            // Uniformity sanity: over many runs each id must reach each index at
            // least once. A Fisher-Yates with a loop-bound off-by-one would pin
            // an element, leaving some (id, position) cell at zero. With a
            // uniform permutation P(cell hit per run) = 1/n, so P(missed over
            // 20k runs) = (3/4)^20000 ≈ 0 for n = 4 — not flaky.
            let ids = [0x03u64, 0x11, 0x09, 0x08];
            let n = ids.len();
            let mut seen = vec![vec![false; n]; n]; // seen[id_index][position]
            for _ in 0..20_000 {
                let mut order: Vec<quinn::VarInt> = ids.iter().map(|&v| vi(v)).collect();
                shuffle_transport_parameter_order(&mut order);
                for (pos, v) in order.iter().enumerate() {
                    let id_idx = ids.iter().position(|&x| x == v.into_inner()).unwrap();
                    seen[id_idx][pos] = true;
                }
            }
            for (id_idx, row) in seen.iter().enumerate() {
                for (pos, &hit) in row.iter().enumerate() {
                    assert!(hit, "id {:#x} never reached position {pos}", ids[id_idx]);
                }
            }
        }
    }

    /// Normal use (no randomization): a session shares the client's exact
    /// fingerprint `Arc` and ticket cache. Guards the `Fingerprint`/
    /// `ClientInner` split against changing default behavior.
    #[test]
    fn default_session_shares_client_fingerprint_and_cache() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build();
        let session = client.session().build();
        assert!(Arc::ptr_eq(
            &session.inner.client.fingerprint,
            &client.fingerprint
        ));
        assert!(Arc::ptr_eq(
            &session.inner.session_store,
            &client.inner.session_store
        ));
    }

    #[test]
    fn partition_context_wraps_client_ticket_cache() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .tls_session_cache_partition_policy(crate::TlsSessionCachePartitionPolicy::Chromium)
            .build();
        let session = client
            .session()
            .network_partition_context(crate::NetworkPartitionContext::new(
                "https://example.com",
                "https://cdn.test",
            ))
            .build();

        assert!(!Arc::ptr_eq(
            &session.inner.session_store,
            &client.inner.session_store
        ));
    }
    /// Per-session synthetic-fingerprint materialization (Tier 3a).
    #[cfg(feature = "synthetic-fp")]
    mod synthetic_fp {
        use super::*;
        use crate::randomize::{Layers, Randomize};

        fn recombine_client() -> Client {
            Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine())
                .build()
        }

        /// A session from a Recombine client materializes a synthesized identity
        /// that is structurally valid on both layers (TLS + H2).
        #[test]
        fn recombine_session_identity_is_valid() {
            let client = recombine_client();
            let session = client.session().build();
            let sc = &session.inner.client;
            assert!(
                lktls::profile::synthesis::validate(sc.tls_profile()).is_ok(),
                "synthesized TLS invalid"
            );
            assert!(
                lkh2::synthesis::validate(sc.h2_profile()).is_ok(),
                "synthesized H2 invalid"
            );
        }

        /// Each session draws its own per-session identity: across many sessions
        /// from one client the TLS fingerprint actually varies.
        #[test]
        fn recombine_sessions_have_distinct_identities() {
            let client = recombine_client();
            let mut sigs = std::collections::HashSet::new();
            for _ in 0..30 {
                let session = client.session().build();
                sigs.insert(session.inner.client.tls_profile().cipher_suites.clone());
            }
            assert!(sigs.len() > 1, "sessions not varied: {}", sigs.len());
        }

        /// A synthetic session must not share the client-level PSK/ticket cache:
        /// resuming another identity's ticket would link two fingerprints.
        #[test]
        fn recombine_session_isolates_psk_cache() {
            let client = recombine_client();
            let session = client.session().build();
            assert!(
                !Arc::ptr_eq(&session.inner.session_store, &client.inner.session_store),
                "synthetic session shared the client ticket cache"
            );
            // Its fingerprint is also a fresh Arc, not the base client's.
            assert!(!Arc::ptr_eq(
                &session.inner.client.fingerprint,
                &client.fingerprint
            ));
        }

        /// `Layers::TLS` synthesizes only TLS — H2 stays byte-identical to the
        /// real base preset, and the PSK cache is isolated (TLS is crypto).
        #[test]
        fn recombine_tls_only_keeps_real_h2() {
            let base_h2 = serde_json::to_string(
                Client::builder()
                    .fingerprint(lktls::profile::presets::chrome_144())
                    .build()
                    .h2_profile(),
            )
            .unwrap();
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine_layers(Layers::TLS))
                .build();
            for _ in 0..20 {
                let s = client.session().build();
                let sc = &s.inner.client;
                assert_eq!(
                    serde_json::to_string(sc.h2_profile()).unwrap(),
                    base_h2,
                    "H2 must be untouched when only TLS is synthesized"
                );
                assert!(lktls::profile::synthesis::validate(sc.tls_profile()).is_ok());
                assert!(
                    !Arc::ptr_eq(&s.inner.session_store, &client.inner.session_store),
                    "synthesizing TLS must isolate the PSK cache"
                );
            }
        }

        /// `Layers::H2` synthesizes only H2 — TLS stays the real preset and the
        /// PSK cache is shared (no crypto-bearing layer synthesized).
        #[test]
        fn recombine_h2_only_keeps_real_tls_and_shares_cache() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine_layers(Layers::H2))
                .build();
            let s = client.session().build();
            let sc = &s.inner.client;
            assert_eq!(
                sc.tls_profile().name,
                "Chrome 144",
                "TLS must stay the real preset when only H2 is synthesized"
            );
            assert!(lkh2::synthesis::validate(sc.h2_profile()).is_ok());
            assert!(
                Arc::ptr_eq(&s.inner.session_store, &client.inner.session_store),
                "H2-only synthesis must share the client PSK cache"
            );
        }

        /// Tier 3b `full_layers(Layers::H2)` perturbs H2 SETTINGS values to novel
        /// numbers — across sessions the value space is far larger than the
        /// handful of fixed values the real presets carry (which is what
        /// `recombine` would reproduce).
        #[test]
        fn full_perturbs_h2_values_per_session() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::full_layers(Layers::H2))
                .build();
            let mut values = std::collections::HashSet::new();
            for _ in 0..50 {
                let s = client.session().build();
                assert!(lkh2::synthesis::validate(s.inner.client.h2_profile()).is_ok());
                for st in &s.inner.client.h2_profile().settings {
                    values.insert((st.id.as_u16(), st.value));
                }
            }
            assert!(
                values.len() > 30,
                "Full did not perturb H2 values: {}",
                values.len()
            );
        }

        /// A QUIC-enabled Recombine client materializes a synthesized QUIC layer
        /// per session (no layer left constant), valid and varied across
        /// sessions. The QUIC-TLS falls back to the synthesized TLS.
        #[cfg(feature = "quic-h3")]
        #[test]
        fn recombine_session_synthesizes_quic_layer() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .quic_profile(lkh3::chrome_146_quic())
                .randomize(Randomize::recombine())
                .build();
            let mut sigs = std::collections::HashSet::new();
            for _ in 0..30 {
                let session = client.session().build();
                let sc = &session.inner.client;
                let q = sc.quic_profile().expect("quic stays enabled");
                assert!(lkh3::synthesis::validate(q).is_ok(), "QUIC invalid");
                // QUIC-TLS reuses the synthesized TLS (no separate profile).
                assert!(sc.quic_tls_profile().is_none());
                sigs.insert((
                    q.h3.settings.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                    q.h3.pseudo_header_order_token(),
                ));
            }
            assert!(
                sigs.len() > 1,
                "QUIC not varied per session: {}",
                sigs.len()
            );
        }
    }
}
