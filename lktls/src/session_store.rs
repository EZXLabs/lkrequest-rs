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
//! SessionStore (trait)
//!   └── InMemorySessionStore (HashMap<String, VecDeque<SessionTicketData>>)
//!         └── per-host FIFO queue (max N tickets per host)
//! ```
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
/// TLS 1.2 tickets (RFC 5077 §3.3) carry a `ticket_lifetime_hint` with weaker
/// semantics — it is only "a hint from the server about how long the ticket
/// should be stored", with no normative ceiling. RFC 5077 does say the client
/// "MAY delete the ticket earlier based on local policy", so the same 7-day
/// bound is applied to TLS 1.2 tickets as *local policy* rather than as a
/// protocol requirement. Both versions cache a long-lived symmetric secret
/// that is worth exactly as much to an attacker, so they get the same cap.
///
/// The lower bound is left alone: a shorter server lifetime always wins, and
/// the TLS 1.3 "value of zero means discard immediately" rule falls out of the
/// comparison in [`SessionTicketData::is_expired`].
pub const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

impl SessionTicketData {
    /// The lifetime this client actually honours for the ticket, in seconds.
    ///
    /// This is the server-advertised [`Self::lifetime_secs`] clamped to
    /// [`MAX_TICKET_LIFETIME_SECS`]; see that constant for why the clamp
    /// applies to both TLS 1.3 and TLS 1.2 tickets.
    pub fn effective_lifetime_secs(&self) -> u32 {
        self.lifetime_secs.min(MAX_TICKET_LIFETIME_SECS)
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

// ---------------------------------------------------------------------------
// SessionStore trait
// ---------------------------------------------------------------------------

/// Trait for storing and retrieving TLS session tickets.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    /// Store a session ticket for the given host.
    ///
    /// `host` is typically `hostname:port` (e.g. `"example.com:443"`).
    fn store(&self, host: &str, ticket: SessionTicketData);

    /// Take a session ticket for the given host, removing it from the store.
    ///
    /// Returns `None` if no valid (non-expired) ticket is available.
    /// Expired tickets are silently discarded.
    fn take(&self, host: &str) -> Option<SessionTicketData>;
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
    store: std::sync::Mutex<std::collections::HashMap<String, VecDeque<SessionTicketData>>>,
    /// Maximum tickets stored per host (default: 2, matching Chrome).
    max_tickets_per_host: usize,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store with default settings.
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host: 2,
        }
    }

    /// Create a new store with a custom per-host ticket limit.
    pub fn with_max_tickets(max_tickets_per_host: usize) -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host,
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
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

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        let mut map = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.get_mut(host)?;

        // Pop from back (most recent ticket first) and skip expired ones
        while let Some(ticket) = queue.pop_back() {
            if !ticket.is_expired() {
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
    use crate::crypto::hkdf::hkdf_expand_label;

    let data = if payload.len() > 4 && payload[0] == 0x04 {
        &payload[4..]
    } else {
        payload
    };

    if data.len() < 12 {
        return Err("NewSessionTicket too short".into());
    }

    let mut pos = 0;

    let lifetime = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let age_add = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    if pos >= data.len() {
        return Err("NewSessionTicket truncated at nonce length".into());
    }
    let nonce_len = data[pos] as usize;
    pos += 1;
    if pos + nonce_len > data.len() {
        return Err("NewSessionTicket truncated at nonce data".into());
    }
    let ticket_nonce = &data[pos..pos + nonce_len];
    pos += nonce_len;

    if pos + 2 > data.len() {
        return Err("NewSessionTicket truncated at ticket length".into());
    }
    let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + ticket_len > data.len() {
        return Err("NewSessionTicket truncated at ticket data".into());
    }
    let ticket = data[pos..pos + ticket_len].to_vec();
    pos += ticket_len;

    let mut max_early_data_size = 0u32;
    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                break;
            }
            if ext_type == 0x002a && ext_len >= 4 {
                max_early_data_size =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            }
            pos += ext_len;
        }
    }

    let hash_len = hkdf_algorithm.hash_len();
    let resumption_psk = hkdf_expand_label(
        hkdf_algorithm,
        resumption_master_secret,
        "resumption",
        ticket_nonce,
        hash_len,
    )
    .map_err(|e| format!("failed to derive resumption PSK: {e}"))?;

    Ok(SessionTicketData {
        ticket,
        resumption_psk,
        tls_version: TicketTlsVersion::Tls13,
        // EMS is a TLS 1.2 concept; the TLS 1.3 key schedule binds the
        // handshake transcript unconditionally.
        used_extended_master_secret: None,
        cipher_suite,
        lifetime_secs: lifetime,
        age_add,
        received_at: Instant::now(),
        alpn,
        alps: AlpsSessionState::Unknown,
        hkdf_algorithm,
        aead_algorithm,
        master_secret: Vec::new(),
        max_early_data_size,
        peer_transport_parameters: None,
    })
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
    let data = if payload.len() > 4 && payload[0] == 0x04 {
        &payload[4..]
    } else {
        payload
    };

    if data.len() < 6 {
        return Err("TLS 1.2 NewSessionTicket too short".into());
    }

    let lifetime_hint = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let ticket_len = u16::from_be_bytes([data[4], data[5]]) as usize;

    if 6 + ticket_len > data.len() {
        return Err("TLS 1.2 NewSessionTicket truncated".into());
    }

    let ticket = data[6..6 + ticket_len].to_vec();

    let (cipher_suite_code, hkdf_alg, aead_alg) = match negotiated_suite {
        Some(suite) => {
            use crate::crypto::prf::PrfAlgorithm;
            let hkdf = match suite.prf_algorithm() {
                PrfAlgorithm::Sha256 => HkdfAlgorithm::Sha256,
                PrfAlgorithm::Sha384 => HkdfAlgorithm::Sha384,
            };
            let aead = if suite.is_aead() {
                match suite.enc_key_len() {
                    32 if matches!(
                        suite,
                        crate::crypto::tls12_cipher::Tls12CipherSuite::EcdheEcdsaChacha20Poly1305
                            | crate::crypto::tls12_cipher::Tls12CipherSuite::EcdheRsaChacha20Poly1305
                    ) => AeadAlgorithm::Chacha20Poly1305,
                    32 => AeadAlgorithm::Aes256Gcm,
                    _ => AeadAlgorithm::Aes128Gcm,
                }
            } else {
                AeadAlgorithm::Aes128Gcm
            };
            (suite.code_point(), hkdf, aead)
        }
        None => (0u16, HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm),
    };

    Ok(SessionTicketData {
        ticket,
        resumption_psk: Vec::new(),
        tls_version: TicketTlsVersion::Tls12,
        used_extended_master_secret,
        cipher_suite: cipher_suite_code,
        lifetime_secs: lifetime_hint,
        age_add: 0,
        received_at: Instant::now(),
        alpn,
        alps: AlpsSessionState::NotNegotiated,
        hkdf_algorithm: hkdf_alg,
        aead_algorithm: aead_alg,
        master_secret: master_secret.to_vec(),
        max_early_data_size: 0,
        peer_transport_parameters: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut payload = vec![0x04, 0x00, 0x00, 0x0b];
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

    /// RFC 5077 §3.3's `ticket_lifetime_hint` is only a hint, and the client
    /// "MAY delete the ticket earlier based on local policy" — so the same
    /// 7-day ceiling is applied to TLS 1.2 tickets.
    #[test]
    fn tls12_ticket_lifetime_hint_is_clamped_to_seven_days() {
        let ticket = make_tls12_ticket(u32::MAX);
        assert_eq!(ticket.tls_version, TicketTlsVersion::Tls12);
        assert_eq!(ticket.effective_lifetime_secs(), MAX_TICKET_LIFETIME_SECS);
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
    fn overlong_lifetime_still_expires_after_seven_days() {
        let cap = Duration::from_secs(MAX_TICKET_LIFETIME_SECS as u64);

        for ticket in [make_ticket(u32::MAX), make_tls12_ticket(u32::MAX)] {
            assert!(
                !ticket.is_expired_at_age(cap),
                "{:?}: exactly 7 days old is still usable",
                ticket.tls_version
            );
            assert!(
                ticket.is_expired_at_age(cap + Duration::from_secs(1)),
                "{:?}: past 7 days the ticket must be treated as expired \
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
