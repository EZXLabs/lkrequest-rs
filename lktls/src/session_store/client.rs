//! Engine-issued client sessions and their verification context.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use rustls_pki_types::TrustAnchor;

use super::{AlpsSessionState, SessionStore, SessionTicketData, TicketTlsVersion};
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::suites::tls13_suite;
use crate::crypto::tls12_cipher::Tls12CipherSuite;
use crate::verify::policy::VerificationPolicy;

/// Storage for opaque sessions issued after a completed client handshake.
///
/// Implement this alongside [`SessionStore`] and return `Some(self)` from
/// [`SessionStore::client_sessions`] to preserve resumption. TLS 1.3 tickets
/// must be removed on take. TLS 1.2 sessions may be reused until expiry;
/// [`ClientSession::clone_tls12`] preserves their authentication provenance.
///
/// There is deliberately no constructor or persistence decoder for
/// [`ClientSession`]. Legacy ticket fields cannot prove peer authentication.
pub trait ClientSessionStore: Send + Sync + fmt::Debug {
    fn store_session(&self, host: &str, session: ClientSession);
    fn take_session(&self, host: &str) -> Option<ClientSession>;
}

/// A versioned client session with engine-recorded authentication provenance.
///
/// Stores may move this value without inspecting secrets. Only a successful
/// handshake can issue it. Its verification context is checked again before
/// use, even when a custom store returns it under a different lookup key.
pub struct ClientSession {
    common: Common,
    protocol: Protocol,
    scope: SessionScope,
}

#[derive(Clone)]
struct Common {
    ticket: Vec<u8>,
    lifetime_secs: u32,
    received_at: Instant,
    alpn: Option<String>,
    cache_ttl: Option<Duration>,
}

enum Protocol {
    Tls12(Tls12Session),
    Tls13(Tls13Session),
}

#[derive(Clone)]
pub(crate) struct Tls12Session {
    pub(crate) session_id: Vec<u8>,
    pub(crate) suite: Tls12CipherSuite,
    pub(crate) master_secret: [u8; 48],
    pub(crate) used_ems: bool,
    pub(crate) state: Tls12SessionState,
}

/// All copies and renewed tickets for one TLS 1.2 session share revocation.
#[derive(Clone, Debug)]
pub(crate) struct Tls12SessionState(Arc<Tls12SessionValidity>);

#[derive(Debug)]
struct Tls12SessionValidity {
    valid: AtomicBool,
    created_at: Instant,
    cache_ttl: OnceLock<Duration>,
}

impl Tls12SessionState {
    pub(crate) fn new(created_at: Instant) -> Self {
        Self(Arc::new(Tls12SessionValidity {
            valid: AtomicBool::new(true),
            created_at,
            cache_ttl: OnceLock::new(),
        }))
    }

    pub(crate) fn invalidate(&self) {
        self.0.valid.store(false, Ordering::Release);
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        let ttl = ttl.min(self.0.cache_ttl.get().copied().unwrap_or(ttl));
        !self.0.valid.load(Ordering::Acquire) || self.0.created_at.elapsed() >= ttl
    }
}

struct Tls13Session {
    suite: u16,
    psk: Vec<u8>,
    age_add: u32,
    max_early_data_size: u32,
    alps: AlpsSessionState,
    peer_transport_parameters: Option<Vec<u8>>,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("version", &self.tls_version())
            .field("cipher_suite", &self.cipher_suite())
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    pub fn tls_version(&self) -> TicketTlsVersion {
        match self.protocol {
            Protocol::Tls12(_) => TicketTlsVersion::Tls12,
            Protocol::Tls13(_) => TicketTlsVersion::Tls13,
        }
    }

    pub fn cipher_suite(&self) -> u16 {
        match &self.protocol {
            Protocol::Tls12(session) => session.suite.code_point(),
            Protocol::Tls13(session) => session.suite,
        }
    }

    /// Whether the session expired or was revoked after a fatal TLS failure.
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_ttl(self.common.cache_ttl)
    }

    pub(super) fn is_expired_with_ttl(&self, ttl: Option<Duration>) -> bool {
        matches!(&self.protocol, Protocol::Tls12(session)
            if session.state.is_expired(super::cache_lifetime(self.tls_version(), ttl)))
            || self.common.received_at.elapsed()
                >= super::effective_cache_lifetime(
                    self.tls_version(),
                    self.common.lifetime_secs,
                    ttl,
                )
    }

    /// Copy a reusable TLS 1.2 session, retaining its original expiry and scope.
    /// TLS 1.3 tickets are single-use and return `None`.
    pub fn clone_tls12(&self) -> Option<Self> {
        let Protocol::Tls12(session) = &self.protocol else {
            return None;
        };
        if self.is_expired() {
            return None;
        }
        Some(Self {
            common: self.common.clone(),
            protocol: Protocol::Tls12(session.clone()),
            scope: self.scope.clone(),
        })
    }

    /// TLS 1.3 early-data allowance, or zero for TLS 1.2.
    pub fn max_early_data_size(&self) -> u32 {
        match &self.protocol {
            Protocol::Tls12(_) => 0,
            Protocol::Tls13(session) => session.max_early_data_size,
        }
    }

    /// Suppress 0-RTT while keeping ordinary authenticated resumption.
    pub fn disable_early_data(&mut self) {
        if let Protocol::Tls13(session) = &mut self.protocol {
            session.max_early_data_size = 0;
        }
    }

    pub(crate) fn ticket(&self) -> &[u8] {
        &self.common.ticket
    }

    pub(crate) fn tls12_session_id(&self) -> Option<&[u8]> {
        match &self.protocol {
            Protocol::Tls12(session) if !session.session_id.is_empty() => Some(&session.session_id),
            _ => None,
        }
    }

    pub(crate) fn tls12_state(&self) -> Option<Tls12SessionState> {
        match &self.protocol {
            Protocol::Tls12(session) => Some(session.state.clone()),
            _ => None,
        }
    }

    pub(crate) fn alpn(&self) -> Option<&str> {
        self.common.alpn.as_deref()
    }

    pub(crate) fn into_tls12(self) -> Option<Tls12Session> {
        match self.protocol {
            Protocol::Tls12(session) => Some(session),
            Protocol::Tls13(_) => None,
        }
    }

    pub(crate) fn from_completed(
        ticket: SessionTicketData,
        scope: SessionScope,
    ) -> Result<Self, &'static str> {
        Self::from_completed_with_id(ticket, scope, Vec::new(), None)
    }

    fn from_completed_with_id(
        ticket: SessionTicketData,
        scope: SessionScope,
        session_id: Vec<u8>,
        state: Option<Tls12SessionState>,
    ) -> Result<Self, &'static str> {
        if session_id.len() > 32
            || (!session_id.is_empty() && ticket.tls_version != TicketTlsVersion::Tls12)
        {
            return Err("invalid TLS 1.2 session ID");
        }
        if (ticket.ticket.is_empty() && session_id.is_empty())
            || ticket.ticket.len() > u16::MAX as usize
        {
            return Err("invalid ticket identity length");
        }
        let protocol = match ticket.tls_version {
            TicketTlsVersion::Tls12 => {
                if scope.transport != Transport::Tcp {
                    return Err("TLS 1.2 session cannot be used over QUIC");
                }
                let suite = Tls12CipherSuite::from_code_point(ticket.cipher_suite)
                    .ok_or("unknown TLS 1.2 session suite")?;
                if ticket.hkdf_algorithm != suite.hash_algorithm()
                    || !ticket.resumption_psk.is_empty()
                    || ticket.max_early_data_size != 0
                    || ticket.peer_transport_parameters.is_some()
                {
                    return Err("inconsistent TLS 1.2 session parameters");
                }
                Protocol::Tls12(Tls12Session {
                    session_id,
                    suite,
                    master_secret: ticket
                        .master_secret
                        .try_into()
                        .map_err(|_| "invalid TLS 1.2 master secret length")?,
                    used_ems: ticket
                        .used_extended_master_secret
                        .ok_or("missing TLS 1.2 EMS history")?,
                    state: state.unwrap_or_else(|| Tls12SessionState::new(ticket.received_at)),
                })
            }
            TicketTlsVersion::Tls13 => {
                let suite =
                    tls13_suite(ticket.cipher_suite).ok_or("unknown TLS 1.3 session suite")?;
                if ticket.hkdf_algorithm != suite.hash
                    || ticket.aead_algorithm != suite.aead
                    || ticket.resumption_psk.len() != suite.hash.hash_len()
                    || !ticket.master_secret.is_empty()
                    || ticket.used_extended_master_secret.is_some()
                {
                    return Err("inconsistent TLS 1.3 session parameters");
                }
                let max_early_data_size = if scope.transport == Transport::Quic
                    && (ticket.max_early_data_size != u32::MAX
                        || ticket.peer_transport_parameters.is_none())
                {
                    0
                } else {
                    ticket.max_early_data_size
                };
                Protocol::Tls13(Tls13Session {
                    suite: ticket.cipher_suite,
                    psk: ticket.resumption_psk,
                    age_add: ticket.age_add,
                    max_early_data_size,
                    alps: ticket.alps,
                    peer_transport_parameters: ticket.peer_transport_parameters,
                })
            }
        };
        Ok(Self {
            common: Common {
                ticket: ticket.ticket,
                lifetime_secs: ticket.lifetime_secs,
                received_at: ticket.received_at,
                alpn: ticket.alpn,
                cache_ttl: None,
            },
            protocol,
            scope,
        })
    }

    pub(crate) fn into_legacy(self) -> SessionTicketData {
        match self.protocol {
            Protocol::Tls12(session) => SessionTicketData {
                ticket: self.common.ticket,
                lifetime_secs: self.common.lifetime_secs,
                received_at: self.common.received_at,
                alpn: self.common.alpn,
                tls_version: TicketTlsVersion::Tls12,
                cipher_suite: session.suite.code_point(),
                hkdf_algorithm: session.suite.hash_algorithm(),
                // Required only by the legacy representation; no fake AEAD
                // is stored in the versioned TLS 1.2 session.
                aead_algorithm: session
                    .suite
                    .descriptor()
                    .protection
                    .aead()
                    .unwrap_or(AeadAlgorithm::Aes128Gcm),
                master_secret: session.master_secret.to_vec(),
                resumption_psk: Vec::new(),
                used_extended_master_secret: Some(session.used_ems),
                age_add: 0,
                max_early_data_size: 0,
                alps: AlpsSessionState::NotNegotiated,
                peer_transport_parameters: None,
            },
            Protocol::Tls13(session) => {
                let suite = tls13_suite(session.suite).expect("validated TLS 1.3 session suite");
                SessionTicketData {
                    ticket: self.common.ticket,
                    lifetime_secs: self.common.lifetime_secs,
                    received_at: self.common.received_at,
                    alpn: self.common.alpn,
                    tls_version: TicketTlsVersion::Tls13,
                    cipher_suite: session.suite,
                    hkdf_algorithm: suite.hash,
                    aead_algorithm: suite.aead,
                    master_secret: Vec::new(),
                    resumption_psk: session.psk,
                    used_extended_master_secret: None,
                    age_add: session.age_add,
                    max_early_data_size: session.max_early_data_size,
                    alps: session.alps,
                    peer_transport_parameters: session.peer_transport_parameters,
                }
            }
        }
    }
}

pub(crate) use crate::config::Transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionScope {
    host: String,
    transport: Transport,
    verification: VerificationPolicy,
    trust_generation: [u8; 32],
}

impl SessionScope {
    pub(crate) fn new(
        hostname: &str,
        port: u16,
        transport: Transport,
        verification: VerificationPolicy,
        anchors: Option<&[TrustAnchor<'_>]>,
    ) -> Self {
        Self {
            host: format!("{hostname}:{port}"),
            transport,
            verification,
            trust_generation: trust_generation(anchors),
        }
    }

    pub(crate) fn from_compiled(
        hostname: &str,
        port: u16,
        config: &crate::config::CompiledClientConfig,
    ) -> Self {
        Self {
            host: format!("{hostname}:{port}"),
            transport: config.transport,
            verification: config.options.verification,
            trust_generation: config.trust_generation,
        }
    }

    pub(crate) fn take(&self, store: &dyn SessionStore) -> Option<ClientSession> {
        let Some(versioned) = store.client_sessions() else {
            tracing::debug!("tls.session_cache_missing_provenance_interface");
            return None;
        };
        let session = versioned.take_session(&self.host)?;
        if session.scope != *self
            || session.is_expired()
            || session.is_expired_with_ttl(store.session_cache_ttl())
        {
            tracing::debug!("tls.session_cache_context_mismatch_or_expired");
            return None;
        }
        Some(session)
    }

    pub(crate) fn store_completed(&self, store: &dyn SessionStore, ticket: SessionTicketData) {
        self.publish_completed(store, ClientSession::from_completed(ticket, self.clone()));
    }

    pub(crate) fn store_tls12_completed(
        &self,
        store: &dyn SessionStore,
        ticket: SessionTicketData,
        session_id: Vec<u8>,
        state: Tls12SessionState,
    ) {
        self.publish_completed(
            store,
            ClientSession::from_completed_with_id(ticket, self.clone(), session_id, Some(state)),
        );
    }

    fn publish_completed(
        &self,
        store: &dyn SessionStore,
        result: Result<ClientSession, &'static str>,
    ) {
        let result = result.map(|mut session| {
            session.common.cache_ttl = store.session_cache_ttl();
            if let Protocol::Tls12(tls12) = &session.protocol {
                // Renewed tickets cannot extend the original secret's TTL.
                let _ = tls12.state.0.cache_ttl.set(super::cache_lifetime(
                    TicketTlsVersion::Tls12,
                    session.common.cache_ttl,
                ));
            }
            session
        });
        match result {
            Ok(session) if !session.is_expired() => {
                if let Some(versioned) = store.client_sessions() {
                    versioned.store_session(&self.host, session);
                } else {
                    // Preserve observation by old custom stores, without
                    // treating their unbound values as resumable next time.
                    store.store(&self.host, session.into_legacy());
                }
            }
            Ok(_) => {}
            Err(reason) => tracing::debug!(reason, "tls.session_cache_invalid_parameters"),
        }
    }

    pub(crate) fn completed_store(&self, inner: Arc<dyn SessionStore>) -> Arc<dyn SessionStore> {
        Arc::new(CompletedSessionStore {
            inner,
            scope: self.clone(),
        })
    }
}

pub(crate) fn trust_generation(anchors: Option<&[TrustAnchor<'_>]>) -> [u8; 32] {
    // Content identity survives Arc cloning/reallocation. Changing verifier
    // semantics requires changing this domain/version as well.
    static ROOTS: OnceLock<[u8; 32]> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| {
        let mut hash = digest::Context::new(&digest::SHA256);
        hash_anchors(&mut hash, webpki_roots::TLS_SERVER_ROOTS);
        hash.finish().as_ref().try_into().unwrap()
    });
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"lktls client verification v1\0");
    hash.update(roots);
    hash_anchors(&mut hash, anchors.unwrap_or_default());
    hash.finish().as_ref().try_into().unwrap()
}

fn hash_anchors(hash: &mut digest::Context, anchors: &[TrustAnchor<'_>]) {
    hash.update(&(anchors.len() as u64).to_be_bytes());
    for anchor in anchors {
        for part in [
            Some(anchor.subject.as_ref()),
            Some(anchor.subject_public_key_info.as_ref()),
            anchor.name_constraints.as_ref().map(|value| value.as_ref()),
        ] {
            hash.update(&[u8::from(part.is_some())]);
            let bytes = part.unwrap_or_default();
            hash.update(&(bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
}

/// Carries the completed handshake's scope through the legacy public ticket
/// context without adding fields to that constructible public struct.
#[derive(Debug)]
struct CompletedSessionStore {
    inner: Arc<dyn SessionStore>,
    scope: SessionScope,
}

impl SessionStore for CompletedSessionStore {
    fn session_cache_ttl(&self) -> Option<Duration> {
        self.inner.session_cache_ttl()
    }

    fn store(&self, host: &str, ticket: SessionTicketData) {
        if host == self.scope.host {
            self.scope.store_completed(self.inner.as_ref(), ticket);
        }
    }

    fn take(&self, _host: &str) -> Option<SessionTicketData> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_store::InMemorySessionStore;
    use crate::session_store::MAX_TICKET_LIFETIME_SECS;

    #[test]
    fn configured_cache_ttl_applies_to_opaque_sessions_including_quic() {
        for (tls12, transport) in [
            (true, Transport::Tcp),
            (false, Transport::Tcp),
            (false, Transport::Quic),
        ] {
            for (ttl, age, expected) in [(60, 61, false), (7200, 3601, true), (0, 0, false)] {
                let store = InMemorySessionStore::new().with_ttl(Duration::from_secs(ttl));
                let mut value = ticket(tls12);
                value.lifetime_secs = 86_400;
                value.received_at = Instant::now() - Duration::from_secs(age);
                scope(transport).store_completed(&store, value);
                let result = scope(transport).take(&store);
                assert_eq!(result.is_some(), expected);
                if let Some(session) = result {
                    assert!(!session.is_expired());
                    assert_eq!(session.clone_tls12().is_some(), tls12);
                }
            }
        }
    }

    #[test]
    fn configured_cache_ttl_preserves_tls12_secret_age_and_revocation() {
        for (ttl, expected) in [(60, false), (7200, true)] {
            let store = InMemorySessionStore::new().with_ttl(Duration::from_secs(ttl));
            let state = Tls12SessionState::new(Instant::now() - Duration::from_secs(3601));
            let mut renewed = ticket(true);
            renewed.lifetime_secs = 0;
            scope(Transport::Tcp).store_tls12_completed(&store, renewed, Vec::new(), state.clone());
            let cached = scope(Transport::Tcp).take(&store);
            assert_eq!(cached.is_some(), expected);
            if let Some(cached) = cached {
                let copy = cached.clone_tls12().unwrap();
                state.invalidate();
                assert!(cached.is_expired());
                assert!(copy.is_expired());
                assert!(scope(Transport::Tcp).take(&store).is_none());
            }
        }
        let state = Tls12SessionState::new(Instant::now() - Duration::from_secs(61));
        state.0.cache_ttl.set(Duration::from_secs(60)).unwrap();
        let longer_store = InMemorySessionStore::new().with_ttl(Duration::from_secs(7200));
        scope(Transport::Tcp).store_tls12_completed(&longer_store, ticket(true), Vec::new(), state);
        assert!(scope(Transport::Tcp).take(&longer_store).is_none());
    }

    #[test]
    fn revoked_tls12_copies_and_renewals_do_not_remove_a_newer_session() {
        let scope = scope(Transport::Tcp);
        let store = InMemorySessionStore::with_max_tickets(3);
        scope.store_completed(&store, ticket(true));
        let failed = scope.take(&store).unwrap();
        let retained_by_custom_store = failed.clone_tls12().unwrap();
        let state = failed.tls12_state().unwrap();
        scope.store_tls12_completed(&store, ticket(true), Vec::new(), state.clone());
        let mut newer = ticket(true);
        newer.ticket = vec![4, 5, 6];
        scope.store_completed(&store, newer);
        std::thread::spawn(move || state.invalidate())
            .join()
            .unwrap();
        assert!(failed.is_expired());
        assert!(retained_by_custom_store.is_expired());
        assert!(retained_by_custom_store.clone_tls12().is_none());
        assert_eq!(scope.take(&store).unwrap().ticket(), &[4, 5, 6]);
        assert!(
            scope.take(&store).is_some(),
            "newer session must remain reusable"
        );
        assert_eq!(
            store
                .store
                .lock()
                .unwrap()
                .get("example.com:443")
                .unwrap()
                .iter()
                .filter(|entry| !entry.is_expired())
                .count(),
            1
        );
    }

    #[test]
    fn renewal_does_not_extend_the_original_tls12_secret_age() {
        let Some(created_at) = Instant::now().checked_sub(Duration::from_secs(
            super::super::MAX_TLS12_SESSION_LIFETIME_SECS as u64 + 1,
        )) else {
            return;
        };
        let store = InMemorySessionStore::new();
        scope(Transport::Tcp).store_tls12_completed(
            &store,
            ticket(true),
            Vec::new(),
            Tls12SessionState::new(created_at),
        );
        assert!(scope(Transport::Tcp).take(&store).is_none());
    }

    #[test]
    fn tls12_record_fatal_alerts_and_errors_revoke_but_close_notify_does_not() {
        for action in 0..5 {
            let store = InMemorySessionStore::new();
            let scope = scope(Transport::Tcp);
            scope.store_completed(&store, ticket(true));
            let session = scope.take(&store).unwrap();
            let state = session.tls12_state().unwrap();
            let mut reader = crate::record::reader::RecordReader::new();
            reader.set_tls12_session_state(state.clone());
            let mut writer = crate::record::writer::RecordWriter::new();
            writer.set_tls12_session_state(state);
            match action {
                0 | 1 => {
                    reader.feed(&[21, 3, 3, 0, 2, if action == 0 { 2 } else { 1 }, 0]);
                    reader.next_record().unwrap().unwrap();
                }
                2 | 3 => {
                    writer
                        .write_record(21, &[if action == 2 { 2 } else { 1 }, 0])
                        .unwrap();
                }
                _ => {
                    reader.feed(&[22, 3, 3, 0xff, 0xff]);
                    assert!(reader.next_record().is_err());
                }
            }
            assert_eq!(scope.take(&store).is_none(), matches!(action, 0 | 2 | 4));
        }
    }

    fn scope(transport: Transport) -> SessionScope {
        SessionScope::new(
            "example.com",
            443,
            transport,
            VerificationPolicy::Strict,
            None,
        )
    }

    fn ticket(tls12: bool) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![1, 2, 3],
            resumption_psk: if tls12 { Vec::new() } else { vec![0x5a; 32] },
            tls_version: if tls12 {
                TicketTlsVersion::Tls12
            } else {
                TicketTlsVersion::Tls13
            },
            cipher_suite: if tls12 { 0xc013 } else { 0x1301 },
            lifetime_secs: 3600,
            age_add: 17,
            received_at: Instant::now(),
            alpn: Some("h2".into()),
            alps: AlpsSessionState::NotNegotiated,
            hkdf_algorithm: crate::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: if tls12 { vec![0xa5; 48] } else { Vec::new() },
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: tls12.then_some(true),
        }
    }

    #[test]
    fn legacy_values_cannot_be_promoted_to_authenticated_sessions() {
        let store = InMemorySessionStore::new();
        for tls12 in [false, true] {
            store.store("example.com:443", ticket(tls12));
            assert!(scope(Transport::Tcp).take(&store).is_none());
            assert!(store.take("example.com:443").is_none());
        }
    }

    #[test]
    fn protocol_parameters_are_validated_and_secrets_are_not_debugged() {
        for tls12 in [false, true] {
            for invalid in 0..7 {
                let mut value = ticket(tls12);
                match invalid {
                    0 => value.ticket.clear(),
                    1 => value.cipher_suite = 0xffff,
                    2 => value.hkdf_algorithm = crate::crypto::hkdf::HkdfAlgorithm::Sha384,
                    3 if tls12 => value.master_secret.pop().map(|_| ()).unwrap(),
                    3 => value.resumption_psk.pop().map(|_| ()).unwrap(),
                    4 if tls12 => value.used_extended_master_secret = None,
                    4 => value.used_extended_master_secret = Some(false),
                    5 if tls12 => value.resumption_psk.push(0),
                    5 => value.master_secret.push(0),
                    6 if tls12 => value.max_early_data_size = 1,
                    6 => value.aead_algorithm = AeadAlgorithm::Chacha20Poly1305,
                    _ => unreachable!(),
                }
                assert!(
                    ClientSession::from_completed(value, scope(Transport::Tcp)).is_err(),
                    "TLS12={tls12}, case={invalid}"
                );
            }
            let session =
                ClientSession::from_completed(ticket(tls12), scope(Transport::Tcp)).unwrap();
            assert_eq!(session.cipher_suite(), if tls12 { 0xc013 } else { 0x1301 });
            let debug = format!("{session:?}");
            assert!(
                !debug.contains("master_secret")
                    && !debug.contains("psk")
                    && !debug.contains("90, 90")
            );
        }
    }

    #[test]
    fn session_scope_binds_peer_port_transport_policy_and_trust_content() {
        let issued = scope(Transport::Tcp);
        let identity = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let anchor =
            crate::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap();
        let changed = [
            SessionScope::new(
                "other.example",
                443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                None,
            ),
            SessionScope::new(
                "example.com",
                8443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                None,
            ),
            scope(Transport::Quic),
            SessionScope::new(
                "example.com",
                443,
                Transport::Tcp,
                VerificationPolicy::Insecure,
                None,
            ),
            SessionScope::new(
                "example.com",
                443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                Some(std::slice::from_ref(&anchor)),
            ),
        ];
        for requested in changed {
            assert_ne!(issued, requested);
        }
        let roots = vec![anchor];
        let copy = roots.clone();
        assert_eq!(
            SessionScope::new(
                "example.com",
                443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                Some(&roots)
            ),
            SessionScope::new(
                "example.com",
                443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                Some(&copy)
            ),
        );
        assert_eq!(
            issued,
            SessionScope::new(
                "example.com",
                443,
                Transport::Tcp,
                VerificationPolicy::Strict,
                Some(&[])
            )
        );
    }

    #[test]
    fn legacy_and_versioned_cache_access_share_capacity_and_consumption() {
        let store = InMemorySessionStore::with_max_tickets(1);
        let scope = scope(Transport::Tcp);
        scope.store_completed(&store, ticket(false));
        let legacy = store.take("example.com:443").unwrap();
        assert!(scope.take(&store).is_none());
        store.store("example.com:443", legacy);
        assert!(scope.take(&store).is_none());
        scope.store_completed(&store, ticket(true));
        scope.store_completed(&store, ticket(false));
        assert_eq!(
            scope.take(&store).unwrap().tls_version(),
            TicketTlsVersion::Tls13
        );
        assert!(scope.take(&store).is_none());
        let disabled = InMemorySessionStore::with_max_tickets(0);
        scope.store_completed(&disabled, ticket(false));
        assert!(scope.take(&disabled).is_none());
    }

    #[test]
    fn early_data_wrappers_preserve_session_provenance() {
        let store = Arc::new(InMemorySessionStore::new().with_ttl(Duration::from_secs(7200)));
        let scope = scope(Transport::Quic);
        let mut value = ticket(false);
        value.max_early_data_size = u32::MAX;
        value.peer_transport_parameters = Some(vec![1, 0]);
        scope.store_completed(store.as_ref(), value);
        let wrapper = crate::trust_anchor::WithoutEarlyData(store);
        assert_eq!(wrapper.session_cache_ttl(), Some(Duration::from_secs(7200)));
        let session = scope.take(&wrapper).unwrap();
        assert_eq!(session.tls_version(), TicketTlsVersion::Tls13);
        assert_eq!(session.max_early_data_size(), 0);
        assert!(scope.take(&wrapper).is_none());
    }

    #[test]
    fn expired_sessions_and_tls13_zero_lifetime_are_not_published() {
        let store = InMemorySessionStore::new();
        for tls12 in [false, true] {
            let mut expired = ticket(tls12);
            expired.received_at =
                Instant::now() - Duration::from_secs(MAX_TICKET_LIFETIME_SECS as u64 + 1);
            scope(Transport::Tcp).store_completed(&store, expired);
            assert!(store.take_session("example.com:443").is_none());
            let mut zero = ticket(tls12);
            zero.lifetime_secs = 0;
            scope(Transport::Tcp).store_completed(&store, zero);
            assert_eq!(store.take_session("example.com:443").is_some(), tls12);
        }
    }

    #[test]
    fn issue29_tls12_zero_lifetime_is_unspecified() {
        let store = InMemorySessionStore::new();
        let mut value = ticket(true);
        value.lifetime_secs = 0;
        scope(Transport::Tcp).store_completed(&store, value);
        assert!(scope(Transport::Tcp).take(&store).is_some());
    }

    #[test]
    fn issue29_tls12_session_is_reusable_but_tls13_is_consumed() {
        for tls12 in [false, true] {
            let store = InMemorySessionStore::new();
            let scope = scope(Transport::Tcp);
            scope.store_completed(&store, ticket(tls12));
            assert!(scope.take(&store).is_some());
            assert_eq!(scope.take(&store).is_some(), tls12);
            assert_eq!(scope.take(&store).is_some(), tls12);
        }
    }
}
