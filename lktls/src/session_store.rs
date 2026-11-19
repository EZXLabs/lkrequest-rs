//! TLS Session Ticket Store for Session Resumption.
//!
//! Stores NewSessionTicket data (TLS 1.3 PSK / TLS 1.2 Session Ticket) per-host
//! so that subsequent connections can perform abbreviated handshakes instead of
//! full ones. This is a critical anti-detection feature — real browsers always
//! use session resumption on repeat connections.
//!
//! # Architecture
//!
//! ```text
//! SessionStore -- optional ClientSessionStore interface
//!   InMemorySessionStore: bounded per-host queues, latest ticket taken first
//!   ClientSession: version-specific secrets and authentication context
//! ```
//!
//! Handshake drivers resume only engine-issued [`ClientSession`] values. Legacy
//! [`SessionTicketData`] remains available for inspection and low-level APIs;
//! inserting it directly does not establish authentication provenance.
//! Custom stores preserve resumption by implementing [`ClientSessionStore`]
//! and returning it from [`SessionStore::client_sessions`].
//!
//! # Usage
//!
//! ```rust
//! use lktls::session_store::InMemorySessionStore;
//! use std::sync::Arc;
//!
//! let store = Arc::new(InMemorySessionStore::new());
//! // Pass `store` to the TLS connector (in lkrequest) for session resumption.
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::HkdfAlgorithm;

pub(crate) mod client;
pub(crate) mod ticket;
pub use client::{ClientSession, ClientSessionStore};

// ---------------------------------------------------------------------------
// Session ticket data
// ---------------------------------------------------------------------------

/// ALPS state associated with the handshake that established a session ticket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AlpsSessionState {
    /// Legacy or externally supplied ticket with no recorded ALPS history.
    /// Retains legacy early-data eligibility without asserting no negotiation.
    #[default]
    Unknown,
    /// The establishing handshake is known not to have negotiated ALPS.
    NotNegotiated,
    /// ALPS settings negotiated for the ticket's ALPN protocol.
    Negotiated {
        /// Settings sent by the client, including a valid empty payload.
        client_settings: Vec<u8>,
        /// Settings received from the server.
        server_settings: Vec<u8>,
    },
}

/// Data stored for a single TLS session ticket.
///
/// Supports both TLS 1.3 (PSK-based) and TLS 1.2 (session ticket) resumption.
/// This legacy representation has no authentication provenance. Handshake
/// drivers use opaque [`ClientSession`] values through [`ClientSessionStore`].
#[derive(Clone, Debug)]
pub struct SessionTicketData {
    /// The opaque ticket bytes sent by the server.
    pub ticket: Vec<u8>,

    /// TLS 1.3: the resumption PSK derived from `resumption_master_secret`.
    /// TLS 1.2: not used (set to empty).
    pub resumption_psk: Vec<u8>,

    /// TLS version this ticket was issued under.
    pub tls_version: TicketTlsVersion,

    /// The cipher suite negotiated when this ticket was issued.
    /// For TLS 1.3 PSK: used to determine the hash algorithm for binder calculation.
    pub cipher_suite: u16,

    /// Ticket lifetime in seconds (server-specified).
    pub lifetime_secs: u32,

    /// TLS 1.3: `ticket_age_add` — a random value the server uses to obscure
    /// the real ticket age. Added to the actual age when computing
    /// `obfuscated_ticket_age` in the `pre_shared_key` extension.
    pub age_add: u32,

    /// When this ticket was received (local monotonic clock).
    pub received_at: Instant,

    /// The ALPN protocol negotiated when this ticket was issued.
    pub alpn: Option<String>,

    /// Effective ALPS settings, or an explicit unknown/not-negotiated state.
    pub alps: AlpsSessionState,

    /// The HKDF algorithm for this ticket's cipher suite.
    pub hkdf_algorithm: HkdfAlgorithm,

    /// The AEAD algorithm for this ticket's cipher suite.
    pub aead_algorithm: AeadAlgorithm,

    /// TLS 1.2: the master secret from the original handshake.
    /// TLS 1.3: not used (set to empty).
    pub master_secret: Vec<u8>,

    /// TLS 1.3: max_early_data_size from the ticket extensions (0 if not present).
    pub max_early_data_size: u32,

    /// Cached peer QUIC transport parameters associated with this ticket.
    pub peer_transport_parameters: Option<Vec<u8>>,

    /// TLS 1.2: whether the session this ticket resumes negotiated Extended
    /// Master Secret (RFC 7627).
    ///
    /// §5.4 says a client "SHOULD store the extended master secret flag in the
    /// session state" precisely so the §5.3 checks can run on resumption: a
    /// server that adds the extension to a session that lacked it, or drops it
    /// from a session that had it, must abort the abbreviated handshake.
    ///
    /// `None` means the flag was never recorded, and the checks are skipped
    /// rather than guessed. Neither default is safe: assuming `false` would
    /// abort every resumption against the near-universal servers that do
    /// negotiate EMS, and assuming `true` would abort every resumption of a
    /// legacy non-EMS session. Always `None` for TLS 1.3, where EMS does not
    /// exist — its key schedule provides the same binding unconditionally.
    pub used_extended_master_secret: Option<bool>,
}

/// Which TLS version issued this ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketTlsVersion {
    Tls13,
    Tls12,
}

/// The longest a ticket may be cached, in seconds — 604800 (7 days).
///
/// RFC 8446 §4.6.1 makes this a hard client-side rule for TLS 1.3 tickets:
/// "Clients MUST NOT cache tickets for longer than 7 days, regardless of the
/// `ticket_lifetime`, and MAY delete tickets earlier based on local policy."
/// The server's `ticket_lifetime` is therefore an upper bound *request*, not
/// an instruction — a server that sends `0xFFFFFFFF` (≈136 years) does not get
/// to pin a resumption secret in the client for that long.
///
/// TLS 1.2 uses the shorter [`MAX_TLS12_SESSION_LIFETIME_SECS`] local policy.
pub const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

/// Default Chromium-compatible cap for TLS 1.2 tickets and session IDs: one hour.
/// A zero RFC 5077 lifetime hint is unspecified and uses this cap; shorter
/// nonzero server lifetimes take precedence. This is not a protocol ceiling.
pub const MAX_TLS12_SESSION_LIFETIME_SECS: u32 = 3_600;

impl SessionTicketData {
    /// Effective lifetime under the default local policy, in seconds.
    ///
    /// TLS 1.2 zero uses the one-hour local cap. Nonzero lifetimes are capped
    /// at one hour for TLS 1.2 and seven days for TLS 1.3. Stores with an
    /// explicit TTL apply that policy instead when storing and taking values.
    pub fn effective_lifetime_secs(&self) -> u32 {
        effective_lifetime_secs(self.tls_version, self.lifetime_secs)
    }

    /// Check if this ticket has expired.
    ///
    /// Expiry is measured against [`Self::effective_lifetime_secs`], not the
    /// raw server-advertised lifetime.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at_age(self.received_at.elapsed())
    }

    /// [`Self::is_expired`] with the ticket's age supplied explicitly.
    ///
    /// Split out so the expiry rule can be tested without waiting on (or
    /// rewinding) a monotonic clock.
    fn is_expired_at_age(&self, age: Duration) -> bool {
        age > Duration::from_secs(self.effective_lifetime_secs() as u64)
    }

    /// Compute the obfuscated ticket age for TLS 1.3 `pre_shared_key` extension.
    ///
    /// `obfuscated_ticket_age = (age_in_ms + ticket_age_add) mod 2^32`
    pub fn obfuscated_ticket_age(&self) -> u32 {
        let age_ms = self.received_at.elapsed().as_millis() as u32;
        age_ms.wrapping_add(self.age_add)
    }
}

pub(crate) fn effective_lifetime_secs(version: TicketTlsVersion, lifetime: u32) -> u32 {
    effective_cache_lifetime(version, lifetime, None).as_secs() as u32
}

pub(crate) fn cache_lifetime(version: TicketTlsVersion, ttl: Option<Duration>) -> Duration {
    ttl.unwrap_or_else(|| {
        Duration::from_secs(match version {
            TicketTlsVersion::Tls12 => MAX_TLS12_SESSION_LIFETIME_SECS,
            TicketTlsVersion::Tls13 => MAX_TICKET_LIFETIME_SECS,
        } as u64)
    })
}

pub(crate) fn effective_cache_lifetime(
    version: TicketTlsVersion,
    lifetime: u32,
    ttl: Option<Duration>,
) -> Duration {
    let local = cache_lifetime(version, ttl);
    match version {
        TicketTlsVersion::Tls12 if lifetime == 0 => local,
        TicketTlsVersion::Tls12 => local.min(Duration::from_secs(lifetime as u64)),
        TicketTlsVersion::Tls13 => local.min(Duration::from_secs(
            lifetime.min(MAX_TICKET_LIFETIME_SECS) as u64,
        )),
    }
}

// ---------------------------------------------------------------------------
// SessionStore trait
// ---------------------------------------------------------------------------

/// Trait for storing and retrieving TLS session tickets.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    /// Override the local cache lifetime for engine-issued sessions.
    /// `None` uses one hour for TLS 1.2 and seven days for TLS 1.3.
    /// Server lifetimes and the TLS 1.3 seven-day protocol limit still apply.
    /// Zero prevents caching. TLS 1.2 renewal retains the original secret age.
    fn session_cache_ttl(&self) -> Option<Duration> {
        None
    }

    /// Store a session ticket for the given host.
    ///
    /// `host` is typically `hostname:port` (e.g. `"example.com:443"`).
    fn store(&self, host: &str, ticket: SessionTicketData);

    /// Take a session ticket for the given host.
    ///
    /// TLS 1.3 tickets are removed; TLS 1.2 sessions may be reused until expiry.
    /// Returns `None` if no valid (non-expired) ticket is available.
    /// Expired tickets are silently discarded.
    fn take(&self, host: &str) -> Option<SessionTicketData>;

    /// Additive interface for engine-issued sessions with authentication
    /// provenance. Legacy-only stores remain source-compatible but their
    /// values cannot authorize resumption in the handshake drivers.
    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        None
    }
}

// ---------------------------------------------------------------------------
// InMemorySessionStore
// ---------------------------------------------------------------------------

/// In-memory session ticket store using a concurrent hash map.
///
/// Each host has a FIFO queue of tickets. The most recently stored ticket
/// is returned first (LIFO within the queue — Chrome behavior).
///
/// Thread-safe and suitable for concurrent use across multiple tasks.
#[derive(Debug)]
pub struct InMemorySessionStore {
    /// Per-host ticket queues.
    store: std::sync::Mutex<std::collections::HashMap<String, VecDeque<CachedSession>>>,
    /// Maximum tickets stored per host (default: 2, matching Chrome).
    max_tickets_per_host: usize,
    cache_ttl: Option<Duration>,
}

#[derive(Debug)]
enum CachedSession {
    Legacy(SessionTicketData),
    Bound(ClientSession),
}

impl CachedSession {
    fn clone_tls12(&self) -> Option<Self> {
        match self {
            Self::Legacy(ticket) if ticket.tls_version == TicketTlsVersion::Tls12 => {
                Some(Self::Legacy(ticket.clone()))
            }
            Self::Bound(session) => session.clone_tls12().map(Self::Bound),
            _ => None,
        }
    }

    #[cfg(test)]
    fn is_expired(&self) -> bool {
        self.is_expired_with_ttl(None)
    }

    fn is_expired_with_ttl(&self, ttl: Option<Duration>) -> bool {
        match self {
            Self::Legacy(ticket) => {
                ticket.received_at.elapsed()
                    >= effective_cache_lifetime(ticket.tls_version, ticket.lifetime_secs, ttl)
            }
            Self::Bound(session) => session.is_expired() || session.is_expired_with_ttl(ttl),
        }
    }
}

impl InMemorySessionStore {
    /// Create a new in-memory session store with default settings.
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host: 2,
            cache_ttl: None,
        }
    }

    /// Create a new store with a custom per-host ticket limit.
    pub fn with_max_tickets(max_tickets_per_host: usize) -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host,
            cache_ttl: None,
        }
    }

    /// Override the local cache TTL. Zero disables storage and resumption.
    /// Shorter server lifetimes and the TLS 1.3 protocol limit still apply.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn session_cache_ttl(&self) -> Option<Duration> {
        self.cache_ttl
    }

    fn store(&self, host: &str, ticket: SessionTicketData) {
        self.insert(host, CachedSession::Legacy(ticket));
    }

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        self.pop(host, true).map(|value| match value {
            CachedSession::Legacy(ticket) => ticket,
            CachedSession::Bound(session) => session.into_legacy(),
        })
    }

    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        Some(self)
    }
}

impl ClientSessionStore for InMemorySessionStore {
    fn store_session(&self, host: &str, session: ClientSession) {
        self.insert(host, CachedSession::Bound(session));
    }

    fn take_session(&self, host: &str) -> Option<ClientSession> {
        while let Some(value) = self.pop(host, false) {
            match value {
                CachedSession::Bound(session) => return Some(session),
                CachedSession::Legacy(_) => {
                    tracing::debug!("tls.session_cache_legacy_value_discarded")
                }
            }
        }
        None
    }
}

impl InMemorySessionStore {
    fn insert(&self, host: &str, ticket: CachedSession) {
        if self.max_tickets_per_host == 0 || ticket.is_expired_with_ttl(self.cache_ttl) {
            return;
        }
        let mut map = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.entry(host.to_string()).or_default();

        // Evict oldest tickets if at capacity
        while queue.len() >= self.max_tickets_per_host {
            queue.pop_front();
        }

        queue.push_back(ticket);

        tracing::debug!(
            host = host,
            queue_len = queue.len(),
            "session_store.ticket_stored",
        );
    }

    fn pop(&self, host: &str, reuse_legacy: bool) -> Option<CachedSession> {
        let mut map = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.get_mut(host)?;

        // Pop from back (most recent ticket first) and skip expired ones
        while let Some(ticket) = queue.pop_back() {
            if !ticket.is_expired_with_ttl(self.cache_ttl) {
                if reuse_legacy || matches!(ticket, CachedSession::Bound(_)) {
                    if let Some(reusable) = ticket.clone_tls12() {
                        queue.push_back(reusable);
                    }
                }
                tracing::debug!(
                    host = host,
                    remaining = queue.len(),
                    "session_store.ticket_taken",
                );
                return Some(ticket);
            }
            tracing::debug!(host = host, "session_store.ticket_expired_discarded",);
        }

        // All tickets expired; remove the empty queue
        map.remove(host);
        None
    }
}

/// A shared session store reference (Arc-wrapped for multi-task use).
pub type SharedSessionStore = Arc<dyn SessionStore>;

// ---------------------------------------------------------------------------
// Session ticket parsing (Sans-I/O)
// ---------------------------------------------------------------------------

/// Parse a TLS 1.3 NewSessionTicket message into a [`SessionTicketData`].
///
/// `payload` is the raw handshake message (type byte + length + body).
/// The caller provides the cryptographic context from the completed handshake.
pub fn parse_tls13_new_session_ticket(
    payload: &[u8],
    resumption_master_secret: &[u8],
    hkdf_algorithm: HkdfAlgorithm,
    aead_algorithm: AeadAlgorithm,
    cipher_suite: u16,
    alpn: Option<String>,
) -> std::result::Result<SessionTicketData, String> {
    let ticket =
        ticket::Tls13Ticket::parse_legacy_payload(payload).map_err(|error| error.to_string())?;
    ticket
        .into_session(
            resumption_master_secret,
            hkdf_algorithm,
            aead_algorithm,
            cipher_suite,
            alpn,
        )
        .map_err(|error| error.to_string())
}

/// Parse a TLS 1.2 NewSessionTicket message into a [`SessionTicketData`].
///
/// `payload` is the raw handshake message (type byte + length + body).
pub fn parse_tls12_new_session_ticket(
    payload: &[u8],
    master_secret: &[u8],
    alpn: Option<String>,
    negotiated_suite: Option<crate::crypto::tls12_cipher::Tls12CipherSuite>,
    used_extended_master_secret: Option<bool>,
) -> std::result::Result<SessionTicketData, String> {
    ticket::Tls12Ticket::parse_legacy_payload(payload)
        .map(|ticket| {
            ticket.into_session(
                master_secret,
                alpn,
                negotiated_suite,
                used_extended_master_secret,
            )
        })
        .map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_cache_ttl_applies_to_legacy_tickets_and_protocol_limits() {
        for tls12 in [false, true] {
            for (ttl, age, expected) in [(60, 61, false), (7200, 3601, true), (0, 0, false)] {
                let store = InMemorySessionStore::new().with_ttl(Duration::from_secs(ttl));
                let mut value = if tls12 {
                    make_tls12_ticket(86_400)
                } else {
                    make_ticket(86_400)
                };
                value.received_at = Instant::now() - Duration::from_secs(age);
                store.store("example.com:443", value);
                assert_eq!(store.take("example.com:443").is_some(), expected);
            }
        }
        for (version, server, expected) in [
            (TicketTlsVersion::Tls12, 0, 1_000_000),
            (TicketTlsVersion::Tls12, 30, 30),
            (TicketTlsVersion::Tls13, 0, 0),
            (TicketTlsVersion::Tls13, 30, 30),
            (TicketTlsVersion::Tls13, u32::MAX, 604_800),
        ] {
            assert_eq!(
                effective_cache_lifetime(version, server, Some(Duration::from_secs(1_000_000))),
                Duration::from_secs(expected)
            );
        }
    }

    fn make_ticket(lifetime_secs: u32) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x01, 0x02, 0x03],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs,
            age_add: 12345,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        }
    }

    /// RFC 7627 §5.4: the EMS flag must be persisted with the ticket, because
    /// the §5.3 resumption checks in `tls12.rs` are skipped when it is `None`.
    /// Without this the checks compile, pass their own unit tests, and never
    /// run against a real handshake.
    #[test]
    fn tls12_ticket_carries_the_extended_master_secret_flag() {
        // NewSessionTicket body: lifetime(4) + ticket length(2) + ticket.
        let mut payload = vec![0x04, 0x00, 0x00, 0x09];
        payload.extend_from_slice(&3600u32.to_be_bytes());
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        for recorded in [Some(true), Some(false), None] {
            let ticket = parse_tls12_new_session_ticket(
                &payload,
                &[0x11; 48],
                Some("http/1.1".to_string()),
                None,
                recorded,
            )
            .expect("ticket parses");
            assert_eq!(
                ticket.used_extended_master_secret, recorded,
                "the EMS flag must survive into the stored ticket"
            );
        }
    }

    /// EMS does not exist in TLS 1.3 — its key schedule binds the transcript
    /// unconditionally — so a 1.3 ticket must never claim a flag either way.
    #[test]
    fn tls13_tickets_never_record_an_extended_master_secret_flag() {
        let ticket = make_ticket(3600);
        assert_eq!(ticket.tls_version, TicketTlsVersion::Tls13);
        assert_eq!(
            ticket.used_extended_master_secret, None,
            "a TLS 1.3 ticket must not carry an EMS flag"
        );
    }

    #[test]
    fn test_store_and_take() {
        let store = InMemorySessionStore::new();
        let ticket = make_ticket(3600);

        store.store("example.com:443", ticket.clone());
        let taken = store.take("example.com:443");
        assert!(taken.is_some());

        // Should be empty now
        let taken2 = store.take("example.com:443");
        assert!(taken2.is_none());
    }

    #[test]
    fn test_max_tickets_per_host() {
        let store = InMemorySessionStore::with_max_tickets(2);
        let t1 = make_ticket(3600);
        let mut t2 = make_ticket(3600);
        t2.ticket = vec![0x04, 0x05, 0x06];
        let mut t3 = make_ticket(3600);
        t3.ticket = vec![0x07, 0x08, 0x09];

        store.store("example.com:443", t1);
        store.store("example.com:443", t2);
        store.store("example.com:443", t3.clone());

        // Only 2 tickets should remain (t2 and t3, t1 evicted)
        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.ticket, t3.ticket); // Most recent first
    }

    #[test]
    fn test_expired_tickets_discarded() {
        let store = InMemorySessionStore::new();
        let mut ticket = make_ticket(0); // 0-second lifetime = immediately expired
        ticket.received_at = Instant::now() - Duration::from_secs(1);

        store.store("example.com:443", ticket);
        let taken = store.take("example.com:443");
        assert!(taken.is_none());
    }

    #[test]
    fn test_obfuscated_ticket_age() {
        let ticket = SessionTicketData {
            ticket: vec![],
            resumption_psk: vec![],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0xFFFF_0000,
            received_at: Instant::now(),
            alpn: None,
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        };
        // Age is ~0ms, so obfuscated_age ≈ age_add
        let age = ticket.obfuscated_ticket_age();
        // Should be close to age_add (within a few ms)
        assert!(age >= 0xFFFF_0000);
    }

    #[test]
    fn test_different_hosts_independent() {
        let store = InMemorySessionStore::new();
        store.store("a.com:443", make_ticket(3600));
        store.store("b.com:443", make_ticket(3600));

        assert!(store.take("a.com:443").is_some());
        assert!(store.take("b.com:443").is_some());
        assert!(store.take("a.com:443").is_none());
    }

    fn make_tls12_ticket(lifetime_secs: u32) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x10, 0x20, 0x30],
            resumption_psk: Vec::new(),
            tls_version: TicketTlsVersion::Tls12,
            cipher_suite: 0xC02F,
            lifetime_secs,
            age_add: 0,
            received_at: Instant::now(),
            alpn: Some("http/1.1".to_string()),
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: vec![0xBB; 48],
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        }
    }

    #[test]
    fn test_tls12_ticket_version_preserved() {
        let store = InMemorySessionStore::new();
        let ticket = make_tls12_ticket(3600);
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.tls_version, TicketTlsVersion::Tls12);
        assert!(!taken.master_secret.is_empty());
        assert!(taken.resumption_psk.is_empty());
    }

    #[test]
    fn test_tls13_ticket_version_preserved() {
        let store = InMemorySessionStore::new();
        let ticket = make_ticket(3600);
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.tls_version, TicketTlsVersion::Tls13);
        assert!(!taken.resumption_psk.is_empty());
        assert!(taken.master_secret.is_empty());
    }

    #[test]
    fn test_ticket_alpn_stored_correctly() {
        let store = InMemorySessionStore::new();
        let mut ticket = make_ticket(3600);
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.alpn, Some("h2".to_string()));
    }

    // ------------------------------------------------------------------
    // Ticket lifetime ceiling (RFC 8446 §4.6.1 / RFC 5077 §3.3)
    // ------------------------------------------------------------------

    /// RFC 8446 §4.6.1: a TLS 1.3 ticket is never cached longer than 7 days,
    /// "regardless of the ticket_lifetime".
    #[test]
    fn tls13_ticket_lifetime_is_clamped_to_seven_days() {
        for advertised in [
            u32::MAX,
            MAX_TICKET_LIFETIME_SECS + 1,
            365 * 24 * 60 * 60, // a year
        ] {
            let ticket = make_ticket(advertised);
            assert_eq!(ticket.tls_version, TicketTlsVersion::Tls13);
            assert_eq!(
                ticket.effective_lifetime_secs(),
                MAX_TICKET_LIFETIME_SECS,
                "server-advertised lifetime {advertised} must be capped at 7 days"
            );
        }
    }

    #[test]
    fn tls12_sessions_are_capped_at_one_hour() {
        for lifetime in [0, 1, 60, 3600, 7200, u32::MAX] {
            let ticket = make_tls12_ticket(lifetime);
            assert_eq!(
                ticket.effective_lifetime_secs(),
                if lifetime == 0 {
                    MAX_TLS12_SESSION_LIFETIME_SECS
                } else {
                    lifetime.min(MAX_TLS12_SESSION_LIFETIME_SECS)
                }
            );
        }
    }

    /// A lifetime at or below the ceiling is honoured verbatim — the clamp is
    /// an upper bound only, and must not extend a short-lived ticket.
    #[test]
    fn lifetime_below_the_ceiling_is_left_alone() {
        for advertised in [0, 1, 3600, MAX_TICKET_LIFETIME_SECS] {
            assert_eq!(
                make_ticket(advertised).effective_lifetime_secs(),
                advertised,
                "lifetime {advertised} is within the cap and must not change"
            );
        }
    }

    /// The ceiling actually governs expiry: a ticket whose server lifetime is
    /// effectively unbounded still expires once it is older than 7 days.
    #[test]
    fn overlong_lifetime_still_expires_at_the_version_specific_cap() {
        for ticket in [make_ticket(u32::MAX), make_tls12_ticket(u32::MAX)] {
            let cap = Duration::from_secs(ticket.effective_lifetime_secs() as u64);
            assert!(
                !ticket.is_expired_at_age(cap),
                "{:?}: exactly at the cap is still usable",
                ticket.tls_version
            );
            assert!(
                ticket.is_expired_at_age(cap + Duration::from_secs(1)),
                "{:?}: past the cap the ticket must be treated as expired \
                 regardless of the server's lifetime",
                ticket.tls_version
            );
            assert!(
                ticket.is_expired_at_age(Duration::from_secs(30 * 24 * 60 * 60)),
                "{:?}: a month-old ticket must be expired",
                ticket.tls_version
            );
        }
    }

    /// A server-chosen lifetime shorter than the cap still ends the ticket
    /// early — the cap must not become the lifetime.
    #[test]
    fn short_server_lifetime_expires_before_the_ceiling() {
        let ticket = make_ticket(60);
        assert!(!ticket.is_expired_at_age(Duration::from_secs(59)));
        assert!(ticket.is_expired_at_age(Duration::from_secs(61)));
    }

    /// An over-cap ticket that is older than the cap is dropped by the store,
    /// not handed back for resumption.
    #[test]
    fn store_discards_tickets_older_than_the_ceiling() {
        let over_cap = Duration::from_secs(MAX_TICKET_LIFETIME_SECS as u64 + 60);
        let mut ticket = make_ticket(u32::MAX);

        // `Instant` counts from an arbitrary epoch (process/boot start on some
        // platforms), so it cannot always be rewound a full week. Where it
        // can't, the age-parameterised rule above is the coverage.
        match Instant::now().checked_sub(over_cap) {
            Some(received_at) => {
                ticket.received_at = received_at;
                assert!(ticket.is_expired(), "a week-old ticket must be expired");

                let store = InMemorySessionStore::new();
                store.store("example.com:443", ticket);
                assert!(
                    store.take("example.com:443").is_none(),
                    "an over-age ticket must never be returned for resumption"
                );
            }
            None => {
                assert_eq!(ticket.effective_lifetime_secs(), MAX_TICKET_LIFETIME_SECS);
            }
        }
    }
}
