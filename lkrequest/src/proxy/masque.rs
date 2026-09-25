//! MASQUE CONNECT-UDP I/O bridge (RFC 9298 / RFC 9297).
//!
//! `lkmasque` owns the wire format and the tunnel state machine and performs no
//! I/O at all. This module is the other half: it drives that state machine over
//! this workspace's patched `h3` + `quinn` forks and presents each tunnel to the
//! inner QUIC stack as a [`quinn::AsyncUdpSocket`], exactly the way
//! `Socks5UdpSocket` presents a SOCKS5 UDP relay (that module is crate-private,
//! so it is named rather than linked). The inner connection therefore keeps its
//! browser fingerprint: it never learns it is inside a tunnel.
//!
//! ```text
//! MasqueConnection          one outer H3 connection to the proxy
//!  ├── h3 driver task       h3 connections do not drive themselves
//!  ├── datagram pump task   quinn::Connection::read_datagram -> TunnelTable::dispatch
//!  └── per tunnel
//!        ├── stream pump task   RequestStream <-> TunnelDriver (capsules)
//!        └── MasqueUdpSocket    quinn::AsyncUdpSocket for the inner endpoint
//! ```
//!
//! ## What lives where
//!
//! | Concern | Owner |
//! |---|---|
//! | Outer QUIC connection, endpoint, `SendRequest` | [`MasqueConnection`] (an `Arc`) |
//! | Tunnel state machines + inbound queues | `Registry`, one per outer connection |
//! | Outbound datagrams | `MasqueUdpSocket::try_send`, synchronously on the caller's task |
//! | Inbound datagrams | the connection-level datagram pump task |
//! | Capsules in both directions | one stream pump task per tunnel |
//!
//! ## Two deliberate omissions
//!
//! The outer connection is **not** fingerprinted. It uses quinn's own rustls
//! defaults with ALPN `h3`, because a MASQUE proxy is not a site being emulated
//! and pretending otherwise buys nothing (`design/masque-connect-udp-design.md`,
//! "外层连接"). Only the inner connection carries a browser profile.
//!
//! DNS for the proxy host is the caller's job: [`MasqueConnection::connect`]
//! takes an already-resolved [`SocketAddr`](std::net::SocketAddr). The session
//! layer already owns a resolver, and duplicating one here would be a second
//! policy for happy eyeballs, DoH and the rest.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use quinn::udp;
use rustls_pki_types::CertificateDer;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use lkmasque::codec::QuarterStreamId;
use lkmasque::tunnel::{
    AuthHeader, Dispatch, SendOutcome, TunnelAction, TunnelConfig, TunnelDriver, TunnelError,
    TunnelStats, TunnelTable,
};

use crate::error::{Error, ProxyErrorKind, Result};
use crate::proxy::{ProxyConfig, ProxyScheme};

/// ALPN of the outer connection to the proxy. RFC 9298 rides on HTTP/3.
const OUTER_ALPN: &[u8] = b"h3";

/// Datagrams held per tunnel before the inner endpoint reads them.
///
/// Overflow drops the **oldest** queued datagram: a stalled reader should see
/// fresh packets rather than a replay of what it already fell behind on, and
/// dropping is what UDP semantics allow anyway (RFC 9298 §5).
const DEFAULT_INBOX_DEPTH: usize = 512;

/// Outer datagram budget assumed until the peer reports one.
///
/// Only used to construct a tunnel before the first
/// [`quinn::Connection::max_datagram_size`] is available; the real value is
/// applied through [`TunnelTable::set_max_datagram_size`] as soon as it is.
const FALLBACK_MAX_DATAGRAM_SIZE: usize = 1200;

/// Datagrams between two refreshes of the outer path MTU.
const MTU_REFRESH_INTERVAL: u32 = 16;

/// How long [`MasqueUdpPoller`] waits before re-checking outer datagram buffer
/// space.
///
/// quinn exposes no "wake me when the datagram buffer drains" hook — only
/// `send_datagram_wait`, which needs the payload up front and therefore cannot
/// back a `UdpPoller`. Polling is the honest alternative; it only engages after
/// [`MasqueUdpSocket::try_send`] has actually reported `WouldBlock`, i.e. under
/// real congestion.
const WRITABLE_POLL_INTERVAL: Duration = Duration::from_millis(1);

type ClientRequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientSendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Map a `lkmasque` failure onto this crate's proxy error taxonomy.
///
/// A refused tunnel keeps its status code so callers can tell "the proxy said
/// no" from "the proxy misbehaved"; 401/407 are reported as an authentication
/// failure because that is the one a user can act on.
fn tunnel_error(proxy: &str, error: TunnelError) -> Error {
    match error {
        TunnelError::RejectedStatus { status } if status == 401 || status == 407 => Error::proxy(
            ProxyErrorKind::AuthenticationFailed,
            format!("MASQUE proxy {proxy} rejected the CONNECT-UDP credentials (status {status})"),
            None,
        ),
        TunnelError::RejectedStatus { status } => Error::proxy(
            ProxyErrorKind::TunnelRefused {
                status_code: status,
            },
            format!("MASQUE proxy {proxy} refused CONNECT-UDP with status {status}"),
            None,
        ),
        other => Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!("MASQUE tunnel through {proxy} failed: {other}"),
            Some(Box::new(other)),
        ),
    }
}

fn outer_error(proxy: &str, what: &str, error: impl fmt::Display) -> Error {
    Error::proxy(
        ProxyErrorKind::IoError,
        format!("MASQUE outer connection to {proxy}: {what}: {error}"),
        None,
    )
}

// ---------------------------------------------------------------------------
// Outer connection configuration
// ---------------------------------------------------------------------------

/// TLS and socket settings for the outer connection to a MASQUE proxy.
///
/// Deliberately small: everything a browser profile would control is *not* set
/// here, because the outer hop is not emulating a browser.
///
/// # Construction
///
/// `#[non_exhaustive]`: build one from [`Default`] and assign the fields you
/// care about, rather than with a struct literal. [`Default`] is the only entry
/// point and covers every field — each one has a defensible default, so there
/// is nothing a `new()` could ask for that `Default` cannot supply:
///
/// ```rust
/// use lkrequest::proxy::MasqueOuterConfig;
/// use std::time::Duration;
///
/// let mut outer = MasqueOuterConfig::default();
/// outer.use_native_certs = false;
/// outer.tunnel_idle_timeout = Some(Duration::from_secs(30));
/// ```
///
/// The seal is deliberate and it is the last free moment for it: this
/// configuration is the growing end of the MASQUE surface. `verify` arrived
/// after the rest, the C ABI entry points ([`lkrequest-ffi`]'s
/// `lk_masque_config_*`) will want more, and challenge-based proxy
/// authentication will want more again. MASQUE is unreleased, so sealing now
/// costs nothing; sealing later would be a breaking change for every
/// downstream crate that ever wrote a literal.
///
/// Note that `#[non_exhaustive]` also forbids the functional-update shorthand
/// `MasqueOuterConfig { verify: false, ..Default::default() }` — the `..base`
/// syntax is a struct literal too. Assign the fields instead; they all stay
/// `pub` and writable, so only the literal form is sealed.
///
/// [`lkrequest-ffi`]: https://docs.rs/lkrequest-ffi
#[derive(Clone)]
#[non_exhaustive]
pub struct MasqueOuterConfig {
    /// Local address to bind the outer UDP socket to. `None` picks the
    /// wildcard address of the proxy's address family.
    pub bind_addr: Option<SocketAddr>,
    /// SNI / certificate name to verify the proxy against. `None` uses the
    /// proxy host from the [`ProxyConfig`].
    pub server_name: Option<String>,
    /// Trust the operating system's certificate store.
    pub use_native_certs: bool,
    /// Additional trust anchors, e.g. a private CA or a test certificate.
    ///
    /// These are DER; [`add_ca_certs_pem`](Self::add_ca_certs_pem) is the entry
    /// point for the PEM bundle a CA is usually handed out as.
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// Verify the proxy's TLS certificate.
    ///
    /// **Default: `true`**. Set to `false` to skip all certificate
    /// verification **on the connection to the proxy**.
    /// **For development/testing only -- insecure!** This connection is then
    /// completely open to a man in the middle: anything that can answer on the
    /// proxy's address, or get itself in front of it, terminates the outer TLS
    /// connection and receives exactly what the proxy would — every tunnel's
    /// CONNECT-UDP target, plus the traffic pattern of everything the session
    /// does, since the inner QUIC connection rides inside as UDP payloads. The
    /// inner connection's own encryption still holds, so the contents do not
    /// leak; what leaks is which origins the tunnel exists to keep private,
    /// and there is no longer any way to tell that the peer is the chosen
    /// proxy at all.
    ///
    /// It is deliberately separate from
    /// [`ClientBuilder::verify`](crate::client::ClientBuilder::verify), which governs
    /// the *inner* connection to the origin. Neither implies the other, so
    /// debugging one hop against a self-signed certificate never silently
    /// disarms the other.
    ///
    /// When this is `false`, [`use_native_certs`](Self::use_native_certs) and
    /// [`extra_roots`](Self::extra_roots) are not consulted at all, and the
    /// "no trust anchors" error [`outer_client_config`] would otherwise raise
    /// does not apply.
    pub verify: bool,
    /// ALPN protocols to offer. Defaults to `["h3"]`.
    pub alpn: Vec<Vec<u8>>,
    /// Per-tunnel inbound datagram queue depth.
    pub inbox_depth: usize,
    /// Retire a tunnel that has carried nothing for this long.
    ///
    /// `None` means never retire on idleness — the tunnel lives exactly as long
    /// as the inner QUIC connection holding its socket. That is the setting to
    /// pick when a proxy charges per tunnel setup rather than per live tunnel,
    /// and it is honoured all the way up: an outer connection that still has
    /// live tunnels is never retired either, or "never reclaim" would silently
    /// become "reclaim whenever the outer connection happens to go idle".
    ///
    /// Defaults to [`DEFAULT_TUNNEL_IDLE_TIMEOUT`].
    pub tunnel_idle_timeout: Option<Duration>,
    /// Upper bound on the tunnels one outer connection carries.
    ///
    /// Past this many, the least recently active tunnels are closed first. This
    /// is the backstop for `tunnel_idle_timeout: None`, where nothing else
    /// bounds growth: a scraping session visiting thousands of origins would
    /// otherwise pin thousands of tunnels, and the proxy has to hold a UDP
    /// socket for every one of them. `0` disables the bound.
    ///
    /// Defaults to [`DEFAULT_MAX_IDLE_TUNNELS`].
    pub max_idle_tunnels: usize,
}

/// Default for [`MasqueOuterConfig::tunnel_idle_timeout`].
///
/// Long enough that a page's subresource fetches to one origin share a tunnel,
/// short enough that a proxy is not asked to hold sockets for origins the
/// session has moved on from. `design/masque-connect-udp-design.md` lists the
/// real-world value as something only measurement can settle.
pub const DEFAULT_TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Default for [`MasqueOuterConfig::max_idle_tunnels`].
pub const DEFAULT_MAX_IDLE_TUNNELS: usize = 256;

impl Default for MasqueOuterConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            server_name: None,
            use_native_certs: true,
            extra_roots: Vec::new(),
            verify: true,
            alpn: vec![OUTER_ALPN.to_vec()],
            inbox_depth: DEFAULT_INBOX_DEPTH,
            tunnel_idle_timeout: Some(DEFAULT_TUNNEL_IDLE_TIMEOUT),
            max_idle_tunnels: DEFAULT_MAX_IDLE_TUNNELS,
        }
    }
}

impl MasqueOuterConfig {
    /// Append every certificate in a PEM bundle to
    /// [`extra_roots`](Self::extra_roots).
    ///
    /// A private CA is normally distributed as PEM, while `extra_roots` is DER,
    /// so this is the entry point that takes the file as it arrives. It is the
    /// outer-hop counterpart of
    /// [`ClientBuilder::add_ca_certs_pem`](crate::client::ClientBuilder::add_ca_certs_pem)
    /// and, like it, accepts a bundle of several certificates; non-certificate
    /// PEM sections (a private key in the same file, say) are skipped.
    ///
    /// Returns how many certificates were added.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] if a PEM section is malformed, or if the input
    /// contains no certificate at all — the second case is the one that matters
    /// in practice, because a path typo or a DER file fed in by mistake would
    /// otherwise leave the configuration silently unchanged and the proxy
    /// verified against whatever else happened to be trusted. Nothing is
    /// appended when this fails: the bundle is parsed in full first, so a
    /// half-loaded trust store is not a state a caller has to reason about.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::proxy::MasqueOuterConfig;
    ///
    /// let pem = std::fs::read("proxy-ca.pem")?;
    /// let mut outer = MasqueOuterConfig::default();
    /// // A privately-fronted proxy needs nothing from the OS store.
    /// outer.use_native_certs = false;
    /// outer.add_ca_certs_pem(&pem)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_ca_certs_pem(&mut self, pem: &[u8]) -> Result<usize> {
        use rustls_pki_types::pem::PemObject;

        let mut parsed = Vec::new();
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate = certificate.map_err(|e| {
                Error::InvalidConfig(format!(
                    "MASQUE outer trust anchor PEM could not be parsed: {e}"
                ))
            })?;
            parsed.push(certificate);
        }
        if parsed.is_empty() {
            return Err(Error::InvalidConfig(
                "MASQUE outer trust anchor PEM contains no certificate".to_string(),
            ));
        }

        let added = parsed.len();
        self.extra_roots.extend(parsed);
        Ok(added)
    }
}

impl fmt::Debug for MasqueOuterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueOuterConfig")
            .field("bind_addr", &self.bind_addr)
            .field("server_name", &self.server_name)
            .field("use_native_certs", &self.use_native_certs)
            .field("extra_roots", &self.extra_roots.len())
            .field("verify", &self.verify)
            .field("inbox_depth", &self.inbox_depth)
            .field("tunnel_idle_timeout", &self.tunnel_idle_timeout)
            .field("max_idle_tunnels", &self.max_idle_tunnels)
            .finish()
    }
}

// The outer connection's TLS types, named once here rather than spelled out
// through `quinn::rustls::` at every use site below. They come from quinn's
// re-export for the reason `outer_client_config` gives: one rustls, not two.
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::crypto::CryptoProvider;
use quinn::rustls::pki_types::{ServerName, UnixTime};
use quinn::rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// A [`quinn::rustls`] verifier that accepts every certificate.
///
/// Backs [`MasqueOuterConfig::verify`]` = false` and nothing else. It is
/// written here rather than reused because the client's own
/// [`verify(false)`](crate::client::ClientBuilder::verify) lands somewhere else
/// entirely: that path runs through `lktls`'s hand-written TLS stack and its
/// [`VerificationPolicy::Insecure`](lktls::verify::policy::VerificationPolicy),
/// which is not a `rustls` verifier and so cannot be installed on the outer
/// connection's plain `rustls` configuration.
///
/// The signature callbacks still check signatures against the provider's
/// algorithms. Rubber-stamping them would not accept anything extra — the
/// certificate they are checked against has already been waved through — but it
/// would blur what is actually skipped here: the chain and the name.
#[derive(Debug)]
struct SkipOuterVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipOuterVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the outer [`quinn::ClientConfig`] — plain rustls, no browser profile.
///
/// Uses `quinn::rustls` rather than a separate rustls dependency so the
/// configuration cannot be built against a different rustls than the one quinn
/// links (`deps/quinn/quinn/src/lib.rs:75`), and names the `ring` provider
/// explicitly instead of relying on a process-wide default that may not have
/// been installed.
///
/// With [`MasqueOuterConfig::verify`]` = false` the trust anchors are not
/// assembled at all and the verifier is replaced wholesale, so neither an
/// unparseable `extra_roots` entry nor an empty trust store is an error —
/// there is nothing left for either to feed.
pub fn outer_client_config(config: &MasqueOuterConfig) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let builder = quinn::rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| Error::InvalidConfig(format!("MASQUE outer TLS configuration: {e}")))?;

    let mut tls = if config.verify {
        let mut roots = quinn::rustls::RootCertStore::empty();
        if config.use_native_certs {
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
        }
        for cert in &config.extra_roots {
            roots.add(cert.clone()).map_err(|e| {
                Error::InvalidConfig(format!(
                    "MASQUE outer trust anchor is not a valid certificate: {e}"
                ))
            })?;
        }
        if roots.is_empty() {
            return Err(Error::InvalidConfig(
                "MASQUE outer connection has no trust anchors: enable `use_native_certs`, supply \
                 `extra_roots` (or `add_ca_certs_pem`), or — for development only — set `verify: \
                 false`"
                    .to_string(),
            ));
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        tracing::warn!(
            "masque.outer_certificate_verification_disabled: the connection to the MASQUE proxy \
             accepts any certificate and is open to a man in the middle"
        );
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipOuterVerification(provider)))
            .with_no_client_auth()
    };
    tls.alpn_protocols = if config.alpn.is_empty() {
        vec![OUTER_ALPN.to_vec()]
    } else {
        config.alpn.clone()
    };

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Error::InvalidConfig(format!("MASQUE outer QUIC crypto: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// Carry this proxy's credential onto the CONNECT-UDP request.
///
/// The encoding is **not** done here. [`ProxyConfig::http_auth_header`] is the
/// one entry point every header-authenticating proxy path uses — HTTP CONNECT
/// included — and it already folds `auth` into `credential`, renders all three
/// [`ProxyCredential`](crate::proxy::ProxyCredential) variants (`UserPass` as
/// `Basic <base64>`, `Http` as `<scheme> <credentials>`, `Custom` through
/// `ProxyAuthenticator::authorization_value`) and picks the field name from
/// [`ProxyConfig::auth_header`]. Re-deriving any of that here would fork the
/// policy and quietly bypass `Custom`.
///
/// The one transformation left is case: that entry point returns the canonical
/// `Proxy-Authorization` / `Authorization` spelling, while HTTP/3 requires
/// lowercase field names (RFC 9114 §4.2) and `lkmasque` rejects anything else.
pub fn auth_header(proxy: &ProxyConfig) -> Result<Option<AuthHeader>> {
    let Some((name, value)) = proxy.http_auth_header() else {
        return Ok(None);
    };
    let header = AuthHeader::new(name.to_ascii_lowercase(), value).map_err(|e| {
        Error::InvalidConfig(format!(
            "MASQUE proxy {proxy} has an unusable credential: {e}"
        ))
    })?;
    Ok(Some(header))
}

// ---------------------------------------------------------------------------
// Per-tunnel handle: inbound queue + shutdown signal
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InboxState {
    queue: VecDeque<Vec<u8>>,
    waker: Option<Waker>,
    closed: bool,
    dropped: u64,
}

/// The inbound side of one tunnel plus its teardown signal.
///
/// Shared by three owners: the registry (so the datagram pump can find it), the
/// [`MasqueUdpSocket`] (which drains it) and the tunnel's stream pump (which
/// waits on `shutdown`).
struct TunnelHandle {
    quarter_stream_id: QuarterStreamId,
    state: Mutex<InboxState>,
    shutdown: Notify,
    /// Set when the tunnel must be torn down with a stream reset rather than a
    /// clean FIN — RFC 9298 §5 requires aborting the request stream when the
    /// peer sends an oversized payload.
    abort: AtomicBool,
    closing: AtomicBool,
}

impl TunnelHandle {
    fn new(quarter_stream_id: QuarterStreamId) -> Self {
        Self {
            quarter_stream_id,
            state: Mutex::new(InboxState::default()),
            shutdown: Notify::new(),
            abort: AtomicBool::new(false),
            closing: AtomicBool::new(false),
        }
    }

    /// Queue one inbound UDP payload, dropping the oldest on overflow.
    fn push(&self, payload: Vec<u8>, depth: usize) {
        let waker = {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            while state.queue.len() >= depth.max(1) {
                state.queue.pop_front();
                state.dropped += 1;
            }
            state.queue.push_back(payload);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Mark the tunnel as delivering nothing further and wake the reader.
    fn close_inbox(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.closed = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut state = self.state.lock();
        if let Some(payload) = state.queue.pop_front() {
            return Poll::Ready(Some(payload));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        self.state.lock().dropped
    }

    /// Ask the stream pump to tear this tunnel down. Idempotent.
    fn request_close(&self, abort: bool) {
        if abort {
            self.abort.store(true, Ordering::Release);
        }
        if !self.closing.swap(true, Ordering::AcqRel) || abort {
            // `notify_one` stores a permit when no task is waiting yet, so a
            // close raised before the pump reaches its select is not lost.
            self.shutdown.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// Registry: the tunnels multiplexed over one outer connection
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RegistryState {
    table: Option<TunnelTable>,
    handles: HashMap<QuarterStreamId, Arc<TunnelHandle>>,
}

/// Every tunnel on one outer connection, behind a single lock.
///
/// `TunnelTable` and the handle map are guarded together because every
/// interesting operation touches both: dispatch looks up a driver *and* a
/// queue, teardown removes both. Two locks would only offer two orders to get
/// wrong.
struct Registry {
    state: Mutex<RegistryState>,
    inbox_depth: usize,
}

impl Registry {
    fn new(max_datagram_size: usize, inbox_depth: usize) -> Self {
        Self {
            state: Mutex::new(RegistryState {
                table: Some(TunnelTable::new(max_datagram_size)),
                handles: HashMap::new(),
            }),
            inbox_depth,
        }
    }

    fn remove(&self, quarter_stream_id: QuarterStreamId) -> Option<TunnelStats> {
        let mut state = self.state.lock();
        state.handles.remove(&quarter_stream_id);
        state
            .table
            .as_mut()
            .and_then(|table| table.remove(quarter_stream_id))
            .map(|tunnel| tunnel.stats())
    }

    fn len(&self) -> usize {
        self.state.lock().table.as_ref().map_or(0, TunnelTable::len)
    }

    /// Apply a new outer datagram budget to every tunnel (RFC 9298 §5).
    fn set_max_datagram_size(&self, max_datagram_size: usize) {
        let mut state = self.state.lock();
        if let Some(table) = state.table.as_mut() {
            if table.max_datagram_size() != max_datagram_size {
                if let Err(err) = table.set_max_datagram_size(max_datagram_size) {
                    tracing::debug!(error = %err, "masque.mtu_update_failed");
                }
            }
        }
    }

    fn max_datagram_size(&self) -> usize {
        self.state
            .lock()
            .table
            .as_ref()
            .map_or(0, TunnelTable::max_datagram_size)
    }

    fn capacity(&self, quarter_stream_id: QuarterStreamId) -> usize {
        self.state
            .lock()
            .table
            .as_ref()
            .and_then(|table| table.get(quarter_stream_id))
            .map_or(0, TunnelDriver::capacity)
    }

    fn stats(&self, quarter_stream_id: QuarterStreamId) -> Option<TunnelStats> {
        self.state
            .lock()
            .table
            .as_ref()
            .and_then(|table| table.get(quarter_stream_id))
            .map(TunnelDriver::stats)
    }

    /// Every live tunnel with how long it has been idle at `now`.
    ///
    /// Idleness comes from `lkmasque`'s own clock-free bookkeeping
    /// ([`TunnelDriver::touch`] / [`TunnelDriver::idle_for`]); this module is
    /// what supplies the instants, on every datagram in either direction and at
    /// tunnel creation, so a tunnel that has never carried traffic still has a
    /// birth time rather than looking infinitely idle.
    fn idle_tunnels(&self, now: std::time::Instant) -> Vec<(Arc<TunnelHandle>, Duration)> {
        let state = self.state.lock();
        let Some(table) = state.table.as_ref() else {
            return Vec::new();
        };
        table
            .iter()
            .filter_map(|tunnel| {
                let handle = state.handles.get(&tunnel.quarter_stream_id())?;
                Some((
                    handle.clone(),
                    tunnel.idle_for(now).unwrap_or(Duration::ZERO),
                ))
            })
            .collect()
    }

    /// Tear every tunnel down; used when the outer connection goes away.
    fn shutdown_all(&self) {
        let handles: Vec<Arc<TunnelHandle>> = {
            let mut state = self.state.lock();
            state.table = None;
            state.handles.drain().map(|(_, handle)| handle).collect()
        };
        for handle in handles {
            handle.close_inbox();
            handle.request_close(false);
        }
    }
}

/// What one round of [`TunnelDriver::progress`] asked for.
#[derive(Default)]
struct Drained {
    writes: Vec<Bytes>,
    closed: bool,
    gone: bool,
    failure: Option<TunnelError>,
}

/// Run the tunnel's `progress` loop to quiescence, collecting side effects.
///
/// The registry lock is held for the whole loop but released before any of the
/// collected bytes are awaited onto the wire — `progress` is pure bookkeeping,
/// so holding a `parking_lot` mutex across it is cheap, while holding one
/// across `send_data().await` would not be sound.
fn drain_tunnel(registry: &Registry, quarter_stream_id: QuarterStreamId) -> Drained {
    let mut out = Drained::default();
    let mut state = registry.state.lock();
    let Some(tunnel) = state
        .table
        .as_mut()
        .and_then(|table| table.get_mut(quarter_stream_id))
    else {
        out.gone = true;
        return out;
    };
    loop {
        match tunnel.progress() {
            Ok(TunnelAction::SendStream(bytes)) => out.writes.push(Bytes::from(bytes)),
            Ok(TunnelAction::Ready) => {}
            Ok(TunnelAction::Capsule(capsule)) => {
                // RFC 9297 §3.2: unknown capsule types are already framed and
                // skipped correctly by the parser; nothing else is defined for
                // CONNECT-UDP over HTTP/3, where payloads ride QUIC DATAGRAMs.
                tracing::trace!(
                    quarter = quarter_stream_id.value(),
                    capsule_type = capsule.capsule_type,
                    len = capsule.value.len(),
                    "masque.capsule_ignored"
                );
            }
            Ok(TunnelAction::NeedData) => break,
            Ok(TunnelAction::Closed) => {
                out.closed = true;
                break;
            }
            Err(err) => {
                out.failure = Some(err);
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Outer connection
// ---------------------------------------------------------------------------

struct OuterConnection {
    quic: quinn::Connection,
    endpoint: quinn::Endpoint,
    send_request: ClientSendRequest,
    registry: Arc<Registry>,
    /// `:authority` of every CONNECT-UDP request on this connection.
    authority: String,
    auth: Option<AuthHeader>,
    /// Label used in error messages, e.g. `masque://proxy:443`.
    proxy_label: String,
    local_addr: SocketAddr,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl fmt::Debug for OuterConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueOuterConnection")
            .field("proxy", &self.proxy_label)
            .field("remote", &self.quic.remote_address())
            .field("tunnels", &self.registry.len())
            .finish()
    }
}

impl Drop for OuterConnection {
    fn drop(&mut self) {
        self.registry.shutdown_all();
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        self.quic.close(0u32.into(), b"masque client done");
    }
}

/// One outer HTTP/3 connection to a MASQUE proxy, carrying any number of
/// CONNECT-UDP tunnels.
///
/// Cloning shares the connection. Sharing is the point: RFC 9298 multiplexes
/// tunnels precisely so a client does not pay a handshake per target, and one
/// proxy already correlates a session's targets through its credentials and
/// source address. Sharing **across** sessions is a different matter and is not
/// something this type does — the session layer keys these per session.
///
/// The connection outlives its tunnels: every [`MasqueUdpSocket`] holds a
/// reference, so the outer connection is only closed once this handle and every
/// tunnel socket are dropped.
#[derive(Clone, Debug)]
pub struct MasqueConnection {
    inner: Arc<OuterConnection>,
}

impl MasqueConnection {
    /// Establish the outer HTTP/3 connection to `proxy` at `proxy_addr`.
    ///
    /// `proxy_addr` is already resolved — see the module documentation for why
    /// DNS is not done here. The h3 connection driver is spawned internally
    /// because an `h3` connection does not make progress on its own, as is the
    /// connection-level datagram pump.
    pub async fn connect(
        proxy: &ProxyConfig,
        proxy_addr: SocketAddr,
        config: &MasqueOuterConfig,
    ) -> Result<Self> {
        if !matches!(proxy.scheme, ProxyScheme::Masque { .. }) {
            return Err(Error::InvalidConfig(format!(
                "proxy {proxy} is not a MASQUE proxy; CONNECT-UDP needs a `masque://` scheme"
            )));
        }
        proxy.validate()?;

        let (host, port) = proxy.host_port();
        let authority = format!("{host}:{port}");
        let proxy_label = proxy.to_string();
        let auth = auth_header(proxy)?;

        let client_config = outer_client_config(config)?;
        let bind_addr = config.bind_addr.unwrap_or(if proxy_addr.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        });
        let endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| outer_error(&proxy_label, "failed to bind the outer UDP socket", e))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| outer_error(&proxy_label, "outer socket has no local address", e))?;

        let server_name = config
            .server_name
            .clone()
            .unwrap_or_else(|| host.to_string());
        let quic = endpoint
            .connect_with(client_config, proxy_addr, &server_name)
            .map_err(|e| outer_error(&proxy_label, "QUIC connect rejected", e))?
            .await
            .map_err(|e| outer_error(&proxy_label, "QUIC handshake failed", e))?;

        // RFC 9297 §2.1 / RFC 9298: both extended CONNECT and HTTP Datagrams
        // are required. The peer's own SETTINGS are not reachable from a
        // client stream on this fork, and would be ambiguous if they were —
        // see the note in `open_tunnel` for both reasons and for what a proxy
        // running in capsule mode does to us as a result.
        let mut builder = h3::client::builder();
        builder.enable_datagram(true).enable_extended_connect(true);
        let (mut driver, send_request) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(quic.clone()))
            .await
            .map_err(|e| outer_error(&proxy_label, "HTTP/3 setup failed", e))?;

        let driver_task = tokio::spawn(async move {
            // An h3 connection does not drive itself; without this the control
            // streams never progress and no response ever arrives.
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let registry = Arc::new(Registry::new(
            quic.max_datagram_size()
                .unwrap_or(FALLBACK_MAX_DATAGRAM_SIZE),
            config.inbox_depth.max(1),
        ));
        let datagram_task = tokio::spawn(datagram_pump(quic.clone(), registry.clone()));

        tracing::debug!(
            proxy = %proxy_label,
            remote = %proxy_addr,
            local = %local_addr,
            max_datagram_size = registry.max_datagram_size(),
            "masque.outer_connected"
        );

        Ok(Self {
            inner: Arc::new(OuterConnection {
                quic,
                endpoint,
                send_request,
                registry,
                authority,
                auth,
                proxy_label,
                local_addr,
                tasks: Mutex::new(vec![driver_task, datagram_task]),
            }),
        })
    }

    /// Open one CONNECT-UDP tunnel to `target_host:target_port`.
    ///
    /// The target travels in the `:path` (RFC 9298 §3), so the *proxy* resolves
    /// it — this route is remote-DNS, like `socks5h`. The returned socket is
    /// ready for `quinn::Endpoint::connect_with`; feed
    /// [`MasqueUdpSocket::capacity`] into the inner endpoint's MTU settings and
    /// turn its path MTU discovery off, or the inner connection will probe past
    /// what the tunnel can carry.
    pub async fn open_tunnel(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<Arc<MasqueUdpSocket>> {
        let outer = &self.inner;
        let proxy = outer.proxy_label.as_str();

        let mut config = TunnelConfig::new(&outer.authority, target_host, target_port)
            .map_err(|e| tunnel_error(proxy, e))?;
        if let Some(auth) = &outer.auth {
            config = config.with_auth(auth.clone());
        }

        // The request is describable before a driver exists, which is what lets
        // the driver be built with the real Quarter Stream ID below: the stream
        // ID is only known once the request has been sent.
        let described = config.build_request();
        let uri = format!("https://{}{}", outer.authority, described.path);
        let mut builder = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(&uri);
        for (name, value) in &described.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut request = builder.body(()).map_err(|e| {
            Error::InvalidConfig(format!(
                "MASQUE CONNECT-UDP request for {uri} is malformed: {e}"
            ))
        })?;
        // RFC 8441 `:protocol`. `h3` reads it out of the extensions rather than
        // the header map (`deps/h3/h3/src/proto/headers.rs:409-420`).
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);

        let mut send_request = outer.send_request.clone();
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| outer_error(proxy, "CONNECT-UDP request failed", e))?;

        // `h3`'s `StreamId` is the full QUIC stream ID, so it has to be
        // quartered here (RFC 9297 §2.1). That is upstream's convention —
        // `h3-datagram` does the same division — and it is worth saying that
        // this code used to do the opposite: the fork had changed
        // `h3-quinn`'s `send_id` to quinn's `index()`, which is already
        // `id >> 2`, and this call was `QuarterStreamId::new`. Rebasing onto
        // current upstream dropped that change, so the meaning of `id()` moved
        // under it. Dividing a value that is already quartered misroutes every
        // tunnel after the first, which is why
        // `masque_quarter_stream_ids_follow_h3_quinn_numbering` pins the
        // numbering rather than trusting this comment.
        let quarter = QuarterStreamId::from_request_stream_id(stream.id().into_inner())
            .map_err(|e| outer_error(proxy, "CONNECT-UDP request stream id", e))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| outer_error(proxy, "CONNECT-UDP response failed", e))?;

        let max_datagram_size = outer
            .quic
            .max_datagram_size()
            .unwrap_or(FALLBACK_MAX_DATAGRAM_SIZE);
        outer.registry.set_max_datagram_size(max_datagram_size);

        let mut driver = TunnelDriver::new(config, quarter, max_datagram_size)
            .map_err(|e| tunnel_error(proxy, e))?;
        // Advances the state machine past `Connecting`; the description it
        // returns is byte-identical to `described`, which was already sent.
        let _ = driver.start().map_err(|e| tunnel_error(proxy, e))?;
        // Give the tunnel a birth time so the idle policy measures "has carried
        // nothing since it opened" rather than reading `None` and having to
        // guess whether that means brand new or infinitely stale.
        driver.touch(std::time::Instant::now());

        // A field whose value is not UTF-8 keeps its name and loses its value
        // rather than being dropped: what RFC 9297 §3.2 forbids is the
        // *presence* of `content-length` / `content-type` /
        // `transfer-encoding`, so dropping the entry would hide the violation.
        // An unreadable value can only make `capsule-protocol` read as
        // not-true, which is an observation and not a failure.
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        // RFC 9298 §3.5, which imports RFC 9297 §3.2: 2xx, not 204/205/206,
        // and none of the three content fields. Note that
        // `capsule-protocol: ?1` is deliberately *not* required here — see the
        // log below.
        if let Err(err) = driver.feed_response(
            response.status().as_u16(),
            headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        ) {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(tunnel_error(proxy, err));
        }
        // `lkmasque` records what the response said about `capsule-protocol`
        // and leaves the reporting to us, because it has no logger. Sending
        // that header is a SHOULD (RFC 9297 §3.4) and is not one of §3.2's
        // requirements, so none of these cases refuses the tunnel — but each
        // is worth a line, because a proxy that skips a SHOULD is the sort of
        // detail that explains a later surprise.
        match driver.capsule_protocol_header() {
            lkmasque::CapsuleProtocolHeader::Present => {}
            lkmasque::CapsuleProtocolHeader::Absent => tracing::debug!(
                proxy = %proxy,
                "masque.capsule_protocol_header_absent: the proxy omitted `capsule-protocol` \
                 (RFC 9297 §3.4 SHOULD); the Capsule Protocol is in force through the \
                 connect-udp upgrade token and the tunnel continues"
            ),
            lkmasque::CapsuleProtocolHeader::NotTrue => tracing::debug!(
                proxy = %proxy,
                "masque.capsule_protocol_header_not_true: the proxy sent `capsule-protocol` with \
                 a value other than ?1, which RFC 9297 §3.4 gives the same meaning as omitting \
                 it; the tunnel continues"
            ),
            lkmasque::CapsuleProtocolHeader::Repeated => tracing::debug!(
                proxy = %proxy,
                "masque.capsule_protocol_header_repeated: the proxy sent `capsule-protocol` more \
                 than once, so its type is a List and RFC 9297 §3.4 requires treating the field \
                 as absent; no value from it was used"
            ),
            // `CapsuleProtocolHeader` is `#[non_exhaustive]`. Report the value
            // rather than swallowing it: a variant this build does not know
            // about is still something the tunnel observed.
            other => tracing::debug!(
                proxy = %proxy,
                observation = ?other,
                "masque.capsule_protocol_header_unrecognised"
            ),
        }
        // Not checked here, and it is worth writing down exactly why, because
        // there is a real MUST NOT going unsatisfied and two separate reasons
        // the obvious fix does not work.
        //
        // RFC 9297 §2.1: "QUIC DATAGRAM frames MUST NOT be sent until the
        // SETTINGS_H3_DATAGRAM setting has been both sent and received with a
        // value of 1." We send ours (`enable_datagram(true)` above). The
        // peer's half is not reachable from here:
        //
        // 1. `ConnectionState`, the only trait that exposes the peer's
        //    settings, is gated behind h3's
        //    `i-implement-a-third-party-backend-and-opt-into-breaking-changes`
        //    feature (`deps/h3/h3/src/lib.rs:21`), which we do not enable. No
        //    public method on `client::RequestStream` or `SendRequest` offers
        //    it otherwise.
        // 2. Even with that feature on, the value would be **ambiguous**:
        //    `settings()` falls back to `Settings::default()` when the peer's
        //    SETTINGS frame has not arrived yet
        //    (`deps/h3/h3/src/shared_state.rs:70-81`) and that default has
        //    `enable_datagram: false` (`deps/h3/h3/src/config.rs:222`). The
        //    `OnceLock` that would separate "not seen yet" from "seen, and
        //    zero" is private. Failing on the collapsed value would reject a
        //    healthy proxy whose SETTINGS merely lost a race with its own
        //    response.
        //
        // So the fix is a narrow, ungated `peer_h3_datagram() -> Option<bool>`
        // accessor upstreamed to the patched fork on `lkrequest-patches` —
        // which both makes it reachable and keeps the three cases apart.
        //
        // What goes wrong meanwhile: a proxy running in capsule mode
        // (RFC 9297 §2.2) answers 2xx, then ignores every QUIC DATAGRAM we
        // send, and the only symptom is the *inner* QUIC handshake timing out,
        // two layers away from the cause. The one accidental guard is that a
        // proxy which also omits the QUIC `max_datagram_frame_size` transport
        // parameter leaves `max_datagram_size()` at `None`, and the 1200-byte
        // floor in `session` then refuses the route with a clear message.
        match driver.progress() {
            Ok(TunnelAction::Ready) => {}
            Ok(other) => {
                return Err(Error::proxy(
                    ProxyErrorKind::ProtocolError,
                    format!("MASQUE tunnel through {proxy} did not become ready: {other:?}"),
                    None,
                ))
            }
            Err(err) => return Err(tunnel_error(proxy, err)),
        }

        let handle = Arc::new(TunnelHandle::new(quarter));
        {
            let mut state = outer.registry.state.lock();
            let Some(table) = state.table.as_mut() else {
                return Err(outer_error(
                    proxy,
                    "outer connection closed",
                    "registry gone",
                ));
            };
            // Applies the connection-wide datagram budget on the way in.
            table.insert(driver).map_err(|e| tunnel_error(proxy, e))?;
            state.handles.insert(quarter, handle.clone());
        }

        let pump = tokio::spawn(tunnel_stream_pump(
            stream,
            outer.registry.clone(),
            handle.clone(),
        ));

        let socket = Arc::new(MasqueUdpSocket {
            outer: self.inner.clone(),
            handle,
            quarter,
            peer_addr: virtual_peer_addr(target_port),
            target: format!("{target_host}:{target_port}"),
            pump: Mutex::new(Some(pump)),
        });

        tracing::debug!(
            proxy = %proxy,
            target = %socket.target,
            quarter = quarter.value(),
            capacity = socket.capacity(),
            "masque.tunnel_open"
        );

        Ok(socket)
    }

    /// The underlying outer QUIC connection.
    pub fn quic_connection(&self) -> &quinn::Connection {
        &self.inner.quic
    }

    /// The endpoint the outer connection was created on.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.inner.endpoint
    }

    /// Number of live tunnels on this connection.
    pub fn tunnel_count(&self) -> usize {
        self.inner.registry.len()
    }

    /// The outer connection's current maximum datagram size, as last applied to
    /// the tunnels.
    pub fn max_datagram_size(&self) -> usize {
        self.inner.registry.max_datagram_size()
    }

    /// Re-read the outer path MTU and push it into every tunnel.
    ///
    /// The datagram pump does this on its own while traffic flows; this is for
    /// a caller that wants a fresh value before sending anything.
    pub fn refresh_max_datagram_size(&self) -> usize {
        let size = self
            .inner
            .quic
            .max_datagram_size()
            .unwrap_or(FALLBACK_MAX_DATAGRAM_SIZE);
        self.inner.registry.set_max_datagram_size(size);
        size
    }

    /// Whether the outer connection is still usable.
    pub fn is_live(&self) -> bool {
        self.inner.quic.close_reason().is_none()
    }

    /// Apply the tunnel lifecycle policy and return how many tunnels were asked
    /// to close.
    ///
    /// Two rules, in order:
    ///
    /// 1. `idle_timeout: Some(t)` retires every tunnel idle for at least `t`.
    ///    `None` retires nothing — the tunnel then lives exactly as long as the
    ///    inner QUIC connection that holds its socket.
    /// 2. `max_tunnels` bounds what survives rule 1, closing the least recently
    ///    active first. `0` disables the bound. This is what keeps `None` from
    ///    meaning "unbounded", since the proxy holds one UDP socket per tunnel.
    ///
    /// Closing is a request, not an act: the tunnel's stream pump finishes the
    /// request stream with a FIN, so [`Self::tunnel_count`] falls shortly after
    /// this returns rather than during it. The inner QUIC connection on a
    /// retired tunnel sees its socket report the peer as gone, which is the same
    /// path a lost outer connection takes.
    pub fn reap_tunnels(&self, idle_timeout: Option<Duration>, max_tunnels: usize) -> usize {
        let now = std::time::Instant::now();
        let mut live = self.inner.registry.idle_tunnels(now);
        let mut closed = 0usize;

        if let Some(timeout) = idle_timeout {
            live.retain(|(handle, idle)| {
                if *idle < timeout {
                    return true;
                }
                handle.request_close(false);
                closed += 1;
                false
            });
        }

        if max_tunnels > 0 && live.len() > max_tunnels {
            // Most idle first, so the bound sheds the tunnels least likely to be
            // in the middle of a request.
            live.sort_by_key(|(_, idle)| std::cmp::Reverse(*idle));
            for (handle, _) in live.iter().take(live.len() - max_tunnels) {
                handle.request_close(false);
                closed += 1;
            }
        }

        if closed > 0 {
            tracing::debug!(
                proxy = %self.inner.proxy_label,
                closed,
                remaining = self.inner.registry.len(),
                "masque.tunnels_reaped"
            );
        }
        closed
    }
}

/// The address the inner quinn endpoint uses for connection tracking.
///
/// Nothing is ever sent to it: every packet is intercepted by
/// [`MasqueUdpSocket`]. `127.0.0.2` mirrors the placeholder
/// `SocksTarget::quinn_addr` uses for domain targets, so both tunnelled paths
/// look the same in logs.
fn virtual_peer_addr(target_port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 2], target_port))
}

// ---------------------------------------------------------------------------
// Pumps
// ---------------------------------------------------------------------------

/// Connection-level inbound datagram pump.
///
/// `read_datagram` is per connection, not per stream, so demultiplexing has to
/// happen somewhere; [`TunnelTable::dispatch`] does the decoding and this task
/// does the delivery. It holds an `Arc<Registry>` but **not** the
/// `OuterConnection`, so it cannot keep the connection alive by itself.
async fn datagram_pump(quic: quinn::Connection, registry: Arc<Registry>) {
    let depth = registry.inbox_depth;
    let mut since_mtu_check = 0u32;

    loop {
        let datagram = match quic.read_datagram().await {
            Ok(datagram) => datagram,
            Err(err) => {
                tracing::debug!(error = %err, "masque.outer_datagram_stream_ended");
                break;
            }
        };

        since_mtu_check += 1;
        if since_mtu_check >= MTU_REFRESH_INTERVAL {
            since_mtu_check = 0;
            if let Some(size) = quic.max_datagram_size() {
                registry.set_max_datagram_size(size);
            }
        }

        let delivery = {
            let mut state = registry.state.lock();
            let Some(table) = state.table.as_mut() else {
                break;
            };
            match table.dispatch(&datagram) {
                Ok(Dispatch::Deliver {
                    quarter_stream_id,
                    payload,
                }) => {
                    let payload = payload.to_vec();
                    // Inbound traffic counts as activity for the idle policy.
                    if let Some(tunnel) = state
                        .table
                        .as_mut()
                        .and_then(|table| table.get_mut(quarter_stream_id))
                    {
                        tunnel.touch(std::time::Instant::now());
                    }
                    state
                        .handles
                        .get(&quarter_stream_id)
                        .cloned()
                        .map(|handle| (handle, payload))
                }
                Ok(Dispatch::UnknownTunnel { quarter_stream_id }) => {
                    // Ordinary after a tunnel closes: datagrams already in
                    // flight keep arriving.
                    tracing::trace!(
                        quarter = quarter_stream_id.value(),
                        "masque.datagram_unknown_tunnel"
                    );
                    None
                }
                Ok(Dispatch::UnknownContext {
                    quarter_stream_id,
                    context_id,
                }) => {
                    // RFC 9298 §5: dropped and counted, never an error.
                    tracing::trace!(
                        quarter = quarter_stream_id.value(),
                        context_id,
                        "masque.datagram_unknown_context"
                    );
                    None
                }
                Err(TunnelError::PeerPayloadTooLarge { payload_len }) => {
                    // RFC 9298 §5: the receiver MUST abort the request stream.
                    // `dispatch` has already failed that one tunnel's driver;
                    // re-decoding the header is the cheapest way to name it,
                    // and a header that decoded once cannot fail to decode now.
                    //
                    // ONLY REACHABLE FROM `lkmasque`'S UNIT TESTS, NEVER E2E:
                    // the trigger is a peer payload above 65527 bytes, but an
                    // inbound payload arrives inside one outer QUIC DATAGRAM,
                    // which is capped by the outer path MTU (~1350 bytes on
                    // loopback and anywhere else). No test proxy can put 65528
                    // bytes on the wire for this branch to see, so the reset
                    // decision is covered where the state machine lives
                    // (`lkmasque::tunnel`, `TunnelDriver::accept_datagram`) and
                    // only the plumbing below is untested.
                    tracing::warn!(payload_len, "masque.peer_payload_too_large");
                    let doomed =
                        lkmasque::codec::decode_datagram(&datagram)
                            .ok()
                            .and_then(|decoded| {
                                state.handles.get(&decoded.quarter_stream_id()).cloned()
                            });
                    drop(state);
                    if let Some(handle) = doomed {
                        handle.request_close(true);
                    }
                    continue;
                }
                Err(err) => {
                    // Framing damage on an unreliable channel: drop it.
                    tracing::trace!(error = %err, "masque.datagram_decode_failed");
                    None
                }
            }
        };

        if let Some((handle, payload)) = delivery {
            handle.push(payload, depth);
        }
    }

    registry.shutdown_all();
}

/// Per-tunnel request-stream pump.
///
/// The CONNECT-UDP request stream stays open for the life of the tunnel and
/// carries capsules (RFC 9297 §3). This task is also where teardown happens,
/// because finishing a stream needs an `await` and [`Drop`] cannot provide one.
async fn tunnel_stream_pump(
    mut stream: ClientRequestStream,
    registry: Arc<Registry>,
    handle: Arc<TunnelHandle>,
) {
    let quarter = handle.quarter_stream_id;
    let mut finish_cleanly = true;

    loop {
        enum Step {
            Shutdown,
            Data(Bytes),
            End,
            Broken(String),
        }

        let step = tokio::select! {
            biased;
            () = handle.shutdown.notified() => Step::Shutdown,
            received = stream.recv_data() => match received {
                Ok(Some(mut buf)) => Step::Data(buf.copy_to_bytes(buf.remaining())),
                Ok(None) => Step::End,
                Err(err) => Step::Broken(err.to_string()),
            },
        };

        let drained = match step {
            Step::Shutdown => {
                if handle.abort.load(Ordering::Acquire) {
                    finish_cleanly = false;
                    break;
                }
                {
                    let mut state = registry.state.lock();
                    if let Some(tunnel) = state
                        .table
                        .as_mut()
                        .and_then(|table| table.get_mut(quarter))
                    {
                        tunnel.close();
                    }
                }
                drain_tunnel(&registry, quarter)
            }
            Step::Data(bytes) => {
                let fed = {
                    let mut state = registry.state.lock();
                    state
                        .table
                        .as_mut()
                        .and_then(|table| table.get_mut(quarter))
                        .map(|tunnel| tunnel.feed_stream(&bytes))
                };
                match fed {
                    Some(Ok(())) => drain_tunnel(&registry, quarter),
                    Some(Err(err)) => {
                        tracing::debug!(error = %err, "masque.capsule_stream_failed");
                        finish_cleanly = false;
                        break;
                    }
                    None => break,
                }
            }
            Step::End => {
                let ended = {
                    let mut state = registry.state.lock();
                    state
                        .table
                        .as_mut()
                        .and_then(|table| table.get_mut(quarter))
                        .map(TunnelDriver::feed_stream_end)
                };
                if let Some(Err(err)) = ended {
                    // RFC 9297 §3.3: a truncated capsule is a malformed message.
                    tracing::debug!(error = %err, "masque.capsule_stream_truncated");
                    finish_cleanly = false;
                    break;
                }
                let drained = drain_tunnel(&registry, quarter);
                write_stream(&mut stream, drained.writes).await;
                break;
            }
            Step::Broken(err) => {
                tracing::debug!(error = %err, "masque.request_stream_lost");
                finish_cleanly = false;
                break;
            }
        };

        if let Some(failure) = drained.failure {
            tracing::debug!(error = %failure, "masque.tunnel_failed");
            finish_cleanly = false;
            break;
        }
        if !write_stream(&mut stream, drained.writes).await {
            finish_cleanly = false;
            break;
        }
        if drained.closed || drained.gone {
            break;
        }
    }

    if finish_cleanly {
        // Design: a tunnel is retired with a normal FIN, never a RESET.
        let _ = stream.finish().await;
    } else {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }

    handle.close_inbox();
    let stats = registry.remove(quarter);
    tracing::debug!(
        quarter = quarter.value(),
        clean = finish_cleanly,
        ?stats,
        "masque.tunnel_closed"
    );
}

async fn write_stream(stream: &mut ClientRequestStream, writes: Vec<Bytes>) -> bool {
    for chunk in writes {
        if let Err(err) = stream.send_data(chunk).await {
            tracing::debug!(error = %err, "masque.capsule_write_failed");
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// MasqueUdpSocket — quinn::AsyncUdpSocket adapter
// ---------------------------------------------------------------------------

/// One CONNECT-UDP tunnel, shaped as a UDP socket for the inner QUIC stack.
///
/// The inner connection sees an ordinary socket: outbound packets become HTTP
/// Datagrams on the outer connection, inbound ones arrive stripped of their two
/// varint prefixes. GSO, GRO and ECN are all unavailable inside a tunnel.
///
/// Holding this socket keeps the outer [`MasqueConnection`] alive. Dropping it
/// asks the tunnel's stream pump to finish the request stream cleanly.
pub struct MasqueUdpSocket {
    outer: Arc<OuterConnection>,
    handle: Arc<TunnelHandle>,
    quarter: QuarterStreamId,
    peer_addr: SocketAddr,
    target: String,
    pump: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for MasqueUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueUdpSocket")
            .field("proxy", &self.outer.proxy_label)
            .field("target", &self.target)
            .field("quarter_stream_id", &self.quarter.value())
            .finish()
    }
}

impl MasqueUdpSocket {
    /// The address to pass to `quinn::Endpoint::connect_with`.
    ///
    /// A placeholder: the target is named in the tunnel's `:path`, and nothing
    /// is ever sent to this address.
    pub fn quinn_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// The tunnel's Quarter Stream ID (RFC 9297 §2.1).
    pub fn quarter_stream_id(&self) -> QuarterStreamId {
        self.quarter
    }

    /// Inner MTU: payload bytes that fit in one HTTP Datagram right now.
    ///
    /// Use it for the inner endpoint's `initial_mtu` and upper bound, and turn
    /// the inner path MTU discovery **off** — a probe above this value is
    /// silently discarded by the tunnel rather than answered, so PMTUD would
    /// settle on a size the tunnel cannot carry.
    pub fn capacity(&self) -> usize {
        self.outer.registry.capacity(self.quarter)
    }

    /// The outer connection's current maximum datagram size.
    pub fn max_datagram_size(&self) -> usize {
        self.outer.registry.max_datagram_size()
    }

    /// Diagnostic counters for this tunnel, while it is still registered.
    pub fn stats(&self) -> Option<TunnelStats> {
        self.outer.registry.stats(self.quarter)
    }

    /// Inbound datagrams dropped because the inner endpoint fell behind.
    pub fn inbound_drops(&self) -> u64 {
        self.handle.dropped()
    }

    /// The outer connection this tunnel runs on.
    pub fn connection(&self) -> MasqueConnection {
        MasqueConnection {
            inner: self.outer.clone(),
        }
    }

    /// Ask for a clean teardown: the request stream is finished with a FIN and
    /// the tunnel is unregistered. Idempotent, and also run on [`Drop`].
    pub fn close(&self) {
        self.handle.request_close(false);
    }

    /// Wait for the tunnel's stream pump to finish after [`close`](Self::close).
    ///
    /// Only useful in tests and shutdown paths; ordinary users drop the socket
    /// and let the pump retire in the background.
    pub async fn closed(&self) {
        let pump = self.pump.lock().take();
        if let Some(pump) = pump {
            let _ = pump.await;
        }
    }

    fn is_gone(&self) -> bool {
        self.handle.state.lock().closed
    }
}

impl Drop for MasqueUdpSocket {
    fn drop(&mut self) {
        self.close();
    }
}

impl quinn::AsyncUdpSocket for MasqueUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(MasqueUdpPoller {
            socket: self,
            fut: None,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if self.is_gone() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MASQUE tunnel is closed",
            ));
        }

        // Outer flow control comes first: `send_payload` mutates the driver's
        // counters, so reporting `WouldBlock` afterwards would double-count the
        // retry. The bound is the payload plus the two varint prefixes, which
        // never exceed eight bytes each.
        //
        // NOT COVERED BY AUTOMATED TESTS: this `WouldBlock` branch, and with it
        // `MasqueUdpPoller::poll_writable`'s waiting loop, only runs once the
        // outer connection's datagram send buffer is genuinely full (1 MiB by
        // default in quinn, drained by the outer connection's own send task).
        // A local test proxy drains it far faster than a test can fill it, and
        // quinn exposes no hook to shrink or stall that buffer from the client
        // side, so there is no deterministic way to reach this line from an
        // end-to-end test. Reviewers: treat it as unverified, not as covered.
        let upper_bound = transmit.contents.len() + 16;
        if self.outer.quic.datagram_send_buffer_space() < upper_bound {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let encoded = {
            let mut state = self.outer.registry.state.lock();
            let Some(tunnel) = state
                .table
                .as_mut()
                .and_then(|table| table.get_mut(self.quarter))
            else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MASQUE tunnel is no longer registered",
                ));
            };
            match tunnel.send_payload(transmit.contents) {
                Ok(SendOutcome::Send(bytes)) => {
                    // Outbound traffic counts as activity too, so a tunnel the
                    // inner connection is only *sending* on (an upload, or a
                    // stream whose acknowledgements are sparse) is not reaped
                    // out from under it.
                    tunnel.touch(std::time::Instant::now());
                    bytes
                }
                Ok(SendOutcome::Dropped {
                    payload_len,
                    capacity,
                }) => {
                    // RFC 9298 §5: an MTU-limited discard, which is ordinary
                    // UDP behaviour and not an error the sender should see.
                    tracing::trace!(
                        payload_len,
                        capacity,
                        "masque.datagram_dropped_over_capacity"
                    );
                    return Ok(());
                }
                Err(TunnelError::PayloadTooLarge { payload_len }) => {
                    // RFC 9298 §5: MUST NOT be sent. Nothing reached the wire,
                    // so the tunnel stays usable.
                    tracing::debug!(payload_len, "masque.payload_over_protocol_max");
                    return Ok(());
                }
                Err(err) => return Err(io::Error::other(err)),
            }
        };

        match self.outer.quic.send_datagram(Bytes::from(encoded)) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                // The outer path shrank between the capacity check and here.
                tracing::trace!("masque.datagram_rejected_too_large");
                Ok(())
            }
            Err(quinn::SendDatagramError::ConnectionLost(err)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("MASQUE outer connection lost: {err}"),
            )),
            Err(err) => Err(io::Error::other(format!(
                "MASQUE outer connection cannot carry datagrams: {err}"
            ))),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        debug_assert!(!meta.is_empty());

        loop {
            let payload = match self.handle.poll_pop(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "MASQUE tunnel closed",
                    )))
                }
                Poll::Ready(Some(payload)) => payload,
            };

            let buf = &mut *bufs[0];
            if payload.len() > buf.len() {
                // Cannot happen while the inner MTU is derived from the tunnel
                // capacity, but truncating a QUIC packet would be worse than
                // dropping it.
                tracing::debug!(
                    payload_len = payload.len(),
                    buf_len = buf.len(),
                    "masque.inbound_datagram_too_large_for_buffer"
                );
                continue;
            }

            buf[..payload.len()].copy_from_slice(&payload);
            meta[0] = udp::RecvMeta {
                addr: self.peer_addr,
                len: payload.len(),
                stride: payload.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // The outer socket's address. There is no inner one: the inner
        // endpoint's packets never touch a real socket of their own.
        Ok(self.outer.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1 // no GSO inside a tunnel: each packet is its own HTTP Datagram
    }

    fn max_receive_segments(&self) -> usize {
        1 // no GRO inside a tunnel
    }

    fn may_fragment(&self) -> bool {
        // `true` is how a socket tells quinn not to run path MTU discovery:
        // `Endpoint::new_with_abstract_socket` derives `allow_mtud` from
        // `!may_fragment()` (`deps/quinn/quinn/src/endpoint.rs:140`). Inside a
        // tunnel a probe above the capacity is silently discarded rather than
        // answered, so discovery would converge on a size the tunnel cannot
        // carry; the real bound comes from [`Self::capacity`] instead.
        // `Socks5UdpSocket` says the same thing for the same reason.
        true
    }
}

/// Write-readiness for [`MasqueUdpSocket`].
struct MasqueUdpPoller {
    socket: Arc<MasqueUdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for MasqueUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueUdpPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for MasqueUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // SAFETY: nothing in this type is structurally pinned; the boxed future
        // is pinned independently. Mirrors `Socks5UdpPoller`.
        let this = unsafe { self.get_unchecked_mut() };
        if this.fut.is_none() {
            let socket = this.socket.clone();
            this.fut = Some(Box::pin(async move {
                loop {
                    if socket.is_gone() {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "MASQUE tunnel is closed",
                        ));
                    }
                    if let Some(reason) = socket.outer.quic.close_reason() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("MASQUE outer connection lost: {reason}"),
                        ));
                    }
                    if socket.outer.quic.datagram_send_buffer_space() > 0 {
                        return Ok(());
                    }
                    tokio::time::sleep(WRITABLE_POLL_INTERVAL).await;
                }
            }));
        }

        let result = Future::poll(Pin::new(this.fut.as_mut().unwrap()), cx);
        if result.is_ready() {
            this.fut = None;
        }
        result
    }
}

#[cfg(test)]
// `MasqueOuterConfig` is `#[non_exhaustive]`, which does not bind inside the
// crate that declares it — so clippy sees `Default::default()` followed by
// field assignments and suggests the struct literal every caller *outside* this
// crate is forbidden from writing. These tests deliberately build the
// configuration the way a downstream caller has to, so the documented path is
// the one under test.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::proxy::{ProxyAuthHeader, ProxyConfig};

    #[test]
    fn virtual_peer_addr_is_a_placeholder_like_socks5() {
        assert_eq!(
            virtual_peer_addr(443),
            SocketAddr::from(([127, 0, 0, 2], 443))
        );
    }

    #[test]
    fn user_pass_is_encoded_as_basic_on_a_lowercase_field() {
        let proxy = ProxyConfig::parse("masque://user:pass@proxy.example.com:443").unwrap();
        let header = auth_header(&proxy).unwrap().unwrap();
        assert_eq!(header.name(), "proxy-authorization");
        // base64("user:pass")
        assert_eq!(header.value(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn http_credential_is_passed_through_verbatim() {
        let proxy = ProxyConfig::parse("masque://proxy.example.com:443")
            .unwrap()
            .with_http_auth("Preshared", "abc123")
            .unwrap();
        let header = auth_header(&proxy).unwrap().unwrap();
        assert_eq!(header.name(), "proxy-authorization");
        assert_eq!(header.value(), "Preshared abc123");
    }

    #[test]
    fn auth_header_selection_reaches_the_tunnel_request() {
        let proxy = ProxyConfig::parse("masque://user:pass@proxy.example.com:443")
            .unwrap()
            .with_auth_header(ProxyAuthHeader::Authorization);
        let header = auth_header(&proxy).unwrap().unwrap();
        assert_eq!(header.name(), "authorization");
    }

    #[test]
    fn no_credential_means_no_header() {
        let proxy = ProxyConfig::parse("masque://proxy.example.com:443").unwrap();
        assert!(auth_header(&proxy).unwrap().is_none());
    }

    #[test]
    fn outer_config_without_any_trust_anchor_is_rejected() {
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        let err = outer_client_config(&config).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    /// The one default that must never drift: everything else in this
    /// configuration is a tuning knob, this one decides whether the hop to the
    /// proxy is authenticated at all.
    #[test]
    fn verification_is_on_by_default() {
        assert!(MasqueOuterConfig::default().verify);
    }

    /// With verification off there is nothing for a trust anchor to feed, so
    /// the "no anchors" rejection above must not fire — otherwise the escape
    /// hatch would still demand the certificate the caller does not have.
    #[test]
    fn skipping_verification_needs_no_trust_anchor() {
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        config.verify = false;
        // Not a certificate at all: nothing should look at it.
        config.extra_roots = vec![CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF])];
        assert!(
            outer_client_config(&config).is_ok(),
            "verify: false must neither require a trust anchor nor parse the ones given"
        );

        // And the same bytes with verification on are still rejected, so the
        // case above really is the flag's doing.
        let mut verifying = config.clone();
        verifying.verify = true;
        let err = outer_client_config(&verifying).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
    }

    fn self_signed_pem() -> String {
        rcgen::generate_simple_self_signed(vec!["proxy.example.com".to_string()])
            .expect("self-signed certificate")
            .cert
            .pem()
    }

    #[test]
    fn pem_trust_anchors_are_appended_and_usable() {
        let pem = self_signed_pem();
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        assert_eq!(config.add_ca_certs_pem(pem.as_bytes()).unwrap(), 1);
        assert_eq!(config.extra_roots.len(), 1);

        // A second bundle appends rather than replaces.
        let second = self_signed_pem();
        assert_eq!(config.add_ca_certs_pem(second.as_bytes()).unwrap(), 1);
        assert_eq!(config.extra_roots.len(), 2);

        // And what was parsed really is a trust anchor rustls accepts.
        outer_client_config(&config).expect("PEM anchors should configure a client");
    }

    #[test]
    fn a_pem_bundle_with_several_certificates_loads_all_of_them() {
        let bundle = format!("{}{}", self_signed_pem(), self_signed_pem());
        let mut config = MasqueOuterConfig::default();
        assert_eq!(config.add_ca_certs_pem(bundle.as_bytes()).unwrap(), 2);
    }

    /// The failure this entry point exists for: a path typo, a DER file fed in
    /// by mistake, a truncated copy-paste. Any of them silently leaving the
    /// trust store as it was is how a proxy ends up verified against the OS
    /// store nobody meant to use.
    #[test]
    fn malformed_pem_is_an_error_and_changes_nothing() {
        for input in [
            &b"not a PEM file at all"[..],
            // A section header with a body that is not base64.
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            // DER handed to the PEM entry point.
            b"\x30\x82\x01\x00",
            b"",
        ] {
            let mut config = MasqueOuterConfig::default();
            let err = config
                .add_ca_certs_pem(input)
                .expect_err("malformed PEM must be reported");
            assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
            assert!(config.extra_roots.is_empty(), "nothing must be appended");
        }
    }

    /// A private key in the same file is skipped, not treated as a failure:
    /// a combined key+certificate PEM is a normal thing to be handed.
    #[test]
    fn non_certificate_pem_sections_are_skipped() {
        let generated = rcgen::generate_simple_self_signed(vec!["proxy.example.com".to_string()])
            .expect("self-signed certificate");
        let bundle = format!(
            "{}{}",
            generated.signing_key.serialize_pem(),
            generated.cert.pem()
        );
        let mut config = MasqueOuterConfig::default();
        assert_eq!(config.add_ca_certs_pem(bundle.as_bytes()).unwrap(), 1);
    }
}
