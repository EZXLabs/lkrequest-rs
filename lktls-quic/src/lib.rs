//! `lktls-quic` — bridge between `lktls`'s byte-exact TLS engine and `quinn`.
//!
//! QUIC carries TLS 1.3 inside its own transport, so a QUIC client must send the
//! *same* browser-exact `ClientHello` and run the same TLS 1.3 key schedule that
//! `lktls` produces for TCP TLS — otherwise the QUIC handshake fingerprint
//! diverges from the TCP one. This crate implements `quinn-proto`'s crypto
//! traits (`Session`, `PacketKey`, `HeaderKey`, `KeyPair`, …) on top of `lktls`,
//! so `quinn` drives an `lktls` [`TlsProfile`] instead of its default rustls
//! backend.
//!
//! The entry point is `LktlsQuicClientConfig`: given a `TlsProfile` (and an
//! optional [`SessionStore`] for TLS
//! resumption / 0-RTT), it produces the QUIC client crypto configuration
//! `quinn` needs. It also exposes `emit_initial_client_hello` so offline
//! fingerprint-regression tests can gate the QUIC `ClientHello` bytes without a
//! network.

use std::any::Any;
use std::fmt;
use std::io;
use std::sync::Arc;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aws_lc_rs::digest;
use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use lktls::config::{
    ClientConfigTemplate, ClientHelloOverrides, CompileOptions, CompiledClientConfig,
    ConnectionInputs, Transport,
};
use lktls::connection::{QuicClientConnection, QuicControlError};
use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::hkdf::{hkdf_expand_label, hkdf_extract};
use lktls::crypto::quic::{
    derive_initial_keys, derive_packet_keys, PacketKeys as LktlsPacketKeys, Side as LktlsSide,
};
use lktls::error::TlsError;
use lktls::extensions::quic_transport_params::encode_transport_params;
use lktls::handshake::driver::{PostHandshakeState, QuicHandshakeDriver, QuicTrafficSecrets};
use lktls::profile::types::TlsProfile;
use lktls::session_store::{SessionStore, SessionTicketData, TicketTlsVersion};
use lktls::verify::policy::VerificationPolicy;
use quinn::ClientConfig as QuinnClientConfig;
use quinn_proto::crypto::{
    self, ClientConfig as ProtoClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey,
    KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};

/// Minimal handshake metadata exposed through `quinn::Connection::handshake_data()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeData {
    pub protocol: Option<Vec<u8>>,
    pub cipher_suite: Option<u16>,
}

/// Builder-style client crypto configuration backed by `lktls`.
#[derive(Clone)]
pub struct LktlsQuicClientConfig {
    template: ClientConfigTemplate,
    handshake: ConnectionInputs,
    port: u16,
}

impl From<TlsProfile> for LktlsQuicClientConfig {
    fn from(profile: TlsProfile) -> Self {
        Self::new(profile)
    }
}

impl LktlsQuicClientConfig {
    pub fn new(profile: TlsProfile) -> Self {
        Self::from_template(ClientConfigTemplate::new(
            profile,
            Transport::Quic,
            CompileOptions::compatibility(),
        ))
        .expect("QUIC template transport")
    }

    pub fn from_compiled(config: Arc<CompiledClientConfig>) -> Result<Self, TlsError> {
        Self::from_template(ClientConfigTemplate::from_compiled(config))
    }

    /// Reuse a lazily compiled template across connections and endpoints.
    pub fn from_template(template: ClientConfigTemplate) -> Result<Self, TlsError> {
        if template.transport() != Transport::Quic {
            return Err(TlsError::InvalidProfile(
                "QUIC connector requires a QUIC configuration".into(),
            ));
        }
        Ok(Self {
            template,
            handshake: ConnectionInputs::new("", 443),
            port: 443,
        })
    }

    pub fn with_profile(mut self, profile: TlsProfile) -> Self {
        self.template = self.template.with_profile(profile);
        self
    }

    pub fn profile(&self) -> &TlsProfile {
        self.template.profile()
    }

    /// Apply per-connection generated values while `profile()` retains the base.
    /// Raw extension conflicts are rejected before selecting a session.
    pub fn client_hello_overrides(mut self, overrides: ClientHelloOverrides) -> Self {
        self.handshake.hello_overrides = overrides;
        self
    }

    pub fn trust_anchor_observer(
        mut self,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Self {
        self.handshake.trust_anchor_observer = Some(observer);
        self
    }

    pub fn full_handshake(mut self) -> Self {
        self.handshake.session_store = None;
        self
    }

    /// Keep the selected ECH/trust settings for a fresh TAI recovery handshake.
    pub fn recovery_config(
        &self,
        profile: TlsProfile,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Self {
        let mut config = self
            .clone()
            .full_handshake()
            .trust_anchor_observer(observer);
        config.template = config.template.with_profile(profile);
        config
    }

    pub fn alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        if self.profile().alpn_protocols == protocols {
            return self;
        }
        let mut profile = self.profile().clone();
        profile.alpn_protocols = protocols;
        self.template = self.template.with_profile(profile);
        self
    }

    /// Retry a TAI hint using a fresh handshake and shared generated encoders.
    /// Generated TAI IDs live in an overlay, while `profile()` retains the base
    /// profile, including raw ALPN/ALPS. Raw TAI profiles retain the
    /// legacy profile replacement path.
    pub fn recovery_with_trust_anchor_ids(
        &self,
        ids: Vec<lktls::trust_anchor::TrustAnchorId>,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Result<Self, TlsError> {
        let (template, overrides) = self
            .template
            .trust_anchor_recovery(ids, &self.handshake.hello_overrides)?;
        let mut config = self
            .clone()
            .full_handshake()
            .trust_anchor_observer(observer);
        config.template = template;
        config.handshake.hello_overrides = overrides;
        Ok(config)
    }

    /// Validate a transport's ALPN requirement against the actual raw offer.
    pub fn require_alpn(mut self, protocols: Vec<String>) -> Self {
        self.handshake.required_alpn = Some(protocols);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self.handshake.port = port;
        self
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.template = self.template.verification_policy(policy);
        self
    }

    pub fn alps_payload(mut self, payload: Vec<u8>) -> Self {
        self.handshake.alps_payload = Some(payload);
        self
    }

    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.handshake.session_store = Some(store);
        self
    }

    pub fn custom_ca_anchors(
        mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) -> Self {
        self.template = self.template.custom_ca_anchors(Some(anchors));
        self
    }

    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.handshake.ech_config_list = Some(config_list);
        self
    }

    /// The ECHConfigList this configuration will offer, if any.
    ///
    /// The [`Debug`] impl elides the whole handshake config, so this is how a
    /// caller (or a test) checks which ECH config a QUIC connection was
    /// actually configured with.
    pub fn ech_config_list(&self) -> Option<&[u8]> {
        self.handshake.ech_config_list.as_deref()
    }

    pub fn keylog(mut self, callback: lktls::KeyLogCallback) -> Self {
        self.handshake.keylog_callback = Some(callback);
        self
    }

    pub fn into_quinn(self) -> QuinnClientConfig {
        QuinnClientConfig::new(Arc::new(self))
    }

    /// Emit the initial QUIC ClientHello bytes for `server_name`.
    ///
    /// Uses the same ticket selection and QUIC early-data eligibility checks as
    /// a real connection, consuming a cached ticket from `server_name:port` when
    /// one is available. An eligible TLS 1.3 ticket permits PSK resumption; the
    /// profile, ticket allowance, and cached peer transport parameters determine
    /// whether `early_data` is offered.
    ///
    /// With real ECH, the returned bytes are the wire ClientHelloOuter; the PSK
    /// identity and binder reside in its encrypted ClientHelloInner.
    /// `transport_params` is the encoded QUIC transport-parameters payload to
    /// embed (tests may pass an arbitrary/empty value).
    ///
    /// Primarily a diagnostic / fingerprint-inspection entry point that bypasses
    /// quinn's `TransportParameters`; the regular path is via
    /// [`quinn_proto::crypto::ClientConfig::start_session`].
    pub fn emit_initial_client_hello(
        &self,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<Vec<u8>, TlsError> {
        let mut driver = self.prepare_quic_handshake(server_name, transport_params)?;
        driver.start()
    }

    fn prepare_quic_handshake(
        &self,
        server_name: &str,
        transport_parameters: Vec<u8>,
    ) -> Result<QuicHandshakeDriver, TlsError> {
        let mut handshake = self.handshake.clone();
        handshake.hostname = server_name.to_string();
        handshake.port = self.port;
        QuicHandshakeDriver::from_compiled(
            self.template.compile()?,
            handshake,
            transport_parameters,
        )
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use lktls::handshake::client_hello_wire::ClientHelloWire;
    use lktls::profile::types::{ext_type, ExtensionSource, ExtensionSpec};
    use lktls::trust_anchor::{TrustAnchorId, TrustAnchorObserver};

    #[test]
    fn generated_overrides_share_compilation_and_preserve_base_profile() {
        let compiled = CompiledClientConfig::compile(
            lktls::profile::presets::chrome_155_quic(),
            Transport::Quic,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let base = LktlsQuicClientConfig::from_compiled(compiled.clone()).unwrap();
        let unchanged = base
            .clone()
            .alpn_protocols(base.profile().alpn_protocols.clone());
        assert!(Arc::ptr_eq(
            &compiled,
            &unchanged.template.compile().unwrap()
        ));
        let changed = base.clone().alpn_protocols(vec!["h3-next".into()]);
        assert_eq!(changed.profile().alpn_protocols, ["h3-next"]);
        let overlay = base.client_hello_overrides(ClientHelloOverrides {
            alpn_protocols: Some(vec!["h3".into(), "h3-next".into()]),
            ..Default::default()
        });
        assert_eq!(overlay.profile().alpn_protocols, ["h3"]);
        assert!(Arc::ptr_eq(&compiled, &overlay.template.compile().unwrap()));
        let wire = ClientHelloWire::parse(
            &overlay
                .emit_initial_client_hello("localhost", vec![])
                .unwrap(),
        )
        .unwrap();
        let ext = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap();
        assert_eq!(
            &wire.handshake[ext.payload.clone()],
            &[0, 11, 2, b'h', b'3', 7, b'h', b'3', b'-', b'n', b'e', b'x', b't']
        );
    }

    #[test]
    fn tai_recovery_selects_generated_overlay_or_legacy_raw_replacement() {
        for (raw_tai, raw_alpn) in [(false, false), (true, false), (false, true)] {
            let mut profile = lktls::profile::presets::chrome_155_quic();
            profile
                .extensions
                .retain(|e| e.extension_type != ext_type::TRUST_ANCHOR_IDS);
            profile.extensions.push(ExtensionSpec {
                extension_type: ext_type::TRUST_ANCHOR_IDS,
                source: if raw_tai {
                    ExtensionSource::RawBytes {
                        data: "00020101".into(),
                    }
                } else {
                    ExtensionSource::TrustAnchorIds {
                        ids: vec!["01".into()],
                        shuffle: false,
                    }
                },
            });
            if raw_alpn {
                profile
                    .extensions
                    .iter_mut()
                    .find(|e| e.extension_type == ext_type::ALPN)
                    .unwrap()
                    .source = ExtensionSource::RawBytes {
                    data: "00070668332d726177".into(),
                };
            }
            let compiled = CompiledClientConfig::compile(
                profile,
                Transport::Quic,
                CompileOptions::compatibility(),
            )
            .unwrap();
            let base = LktlsQuicClientConfig::from_compiled(compiled.clone())
                .unwrap()
                .session_store(Arc::new(lktls::session_store::InMemorySessionStore::new()));
            let id = TrustAnchorId::new(vec![2]).unwrap();
            let observer = TrustAnchorObserver::default();
            let retry = base
                .recovery_with_trust_anchor_ids(vec![id.clone()], observer.clone())
                .unwrap();
            assert_eq!(
                Arc::ptr_eq(&compiled, &retry.template.compile().unwrap()),
                !raw_tai
            );
            assert!(retry.handshake.session_store.is_none());
            let wire = ClientHelloWire::parse(
                &retry
                    .emit_initial_client_hello("localhost", vec![])
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(observer.snapshot().requested_ids, [id]);
            if raw_alpn {
                let ext = wire
                    .extensions
                    .iter()
                    .find(|e| e.extension_type == ext_type::ALPN)
                    .unwrap();
                assert_eq!(
                    &wire.handshake[ext.payload.clone()],
                    &[0, 7, 6, b'h', b'3', b'-', b'r', b'a', b'w']
                );
            }
        }
    }

    #[test]
    fn raw_alpn_override_conflicts_fail_before_ticket_selection() {
        use lktls::session_store::{
            ClientSession, ClientSessionStore, SessionStore, SessionTicketData,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Debug, Default)]
        struct Counter(AtomicUsize);
        impl ClientSessionStore for Counter {
            fn store_session(&self, _: &str, _: ClientSession) {
                panic!("unexpected store")
            }
            fn take_session(&self, _: &str) -> Option<ClientSession> {
                self.0.fetch_add(1, Ordering::SeqCst);
                None
            }
        }
        impl SessionStore for Counter {
            fn store(&self, _: &str, _: SessionTicketData) {
                panic!("unexpected legacy store")
            }
            fn take(&self, _: &str) -> Option<SessionTicketData> {
                panic!("unexpected legacy take")
            }
            fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
                Some(self)
            }
        }
        let mut profile = lktls::profile::presets::chrome_155_quic();
        profile
            .extensions
            .iter_mut()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "0003026833".into(),
        };
        let store = Arc::new(Counter::default());
        let config = LktlsQuicClientConfig::new(profile)
            .session_store(store.clone())
            .client_hello_overrides(ClientHelloOverrides {
                alpn_protocols: Some(vec!["h3-next".into()]),
                ..Default::default()
            });
        assert!(config
            .emit_initial_client_hello("localhost", vec![])
            .is_err());
        assert_eq!(store.0.load(Ordering::SeqCst), 0);
    }
}

impl ProtoClientConfig for LktlsQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        ensure_supported_version(version)?;

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        let driver = self
            .prepare_quic_handshake(server_name, transport_parameters)
            .map_err(|e| map_tls_start_error(server_name, e))?;
        let connection =
            QuicClientConnection::new(driver).map_err(|e| map_tls_start_error(server_name, e))?;

        // Use the TLS driver's actual PSK/early-data offer and transcript,
        // including ClientHelloInner when ECH is active.
        let zero_rtt = connection
            .early_data_offer()
            .filter(|(ticket, _)| {
                // RFC 9001 §4.6.1: over QUIC the only legal `max_early_data_size`
                // is 0xffffffff — QUIC's own flow control bounds early data, so a
                // TLS-level byte budget is meaningless and any other value marks
                // the ticket as not a QUIC early-data ticket. The session core
                // has already suppressed incompatible early-data allowances.
                ticket.tls_version == TicketTlsVersion::Tls13
                    && ticket.max_early_data_size == QUIC_MAX_EARLY_DATA_SIZE
                    && ticket.peer_transport_parameters.is_some()
            })
            .and_then(|(ticket, client_hello)| derive_early_crypto(ticket, client_hello).ok());

        let resumed_ticket = connection.resumption_ticket();
        let peer_transport_parameters =
            resumed_ticket.and_then(|ticket| ticket.peer_transport_parameters.clone());
        tracing::debug!(
            server_name = %server_name,
            version = format_args!("{version:#x}"),
            resumed = resumed_ticket.is_some(),
            zero_rtt = zero_rtt.is_some(),
            "quic.tls_session_started"
        );

        Ok(Box::new(LktlsQuicSession {
            side: Side::Client,
            connection,
            handshake_data: None,
            peer_transport_parameters,
            post_handshake: None,
            zero_rtt,
        }))
    }
}

struct LktlsQuicSession {
    side: Side,
    connection: QuicClientConnection,
    handshake_data: Option<HandshakeData>,
    peer_transport_parameters: Option<Vec<u8>>,
    post_handshake: Option<PostHandshakeState>,
    zero_rtt: Option<ZeroRttState>,
}

impl Session for LktlsQuicSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        let side = match side {
            Side::Client => LktlsSide::Client,
            Side::Server => LktlsSide::Server,
        };
        let keys =
            derive_initial_keys(dst_cid, side).expect("initial key derivation should not fail");
        keys_from_derived(keys)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.handshake_data
            .as_ref()
            .cloned()
            .map(|data| Box::new(data) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.zero_rtt.as_ref().map(|zero_rtt| {
            (
                Box::new(LktlsHeaderProtectionKey::new(
                    &zero_rtt.keys.hp_key,
                    zero_rtt.aead_algorithm,
                )) as Box<dyn HeaderKey>,
                Box::new(packet_key_from_derived(
                    zero_rtt.keys.clone(),
                    zero_rtt.aead_algorithm,
                )) as Box<dyn PacketKey>,
            )
        })
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.zero_rtt.as_ref().map(|zero_rtt| zero_rtt.accepted)
    }

    fn early_data_rejected(&self) -> bool {
        self.zero_rtt
            .as_ref()
            .is_some_and(|zero_rtt| zero_rtt.rejected)
    }

    fn early_data_rejection_allows_stream_reuse(&self) -> bool {
        self.handshake_data.is_some()
            && self.zero_rtt.as_ref().is_some_and(|zero_rtt| {
                zero_rtt.session_resumed
                    && !zero_rtt.accepted
                    && !zero_rtt.rejected
                    && zero_rtt.alpn.as_deref().is_some_and(|alpn| {
                        !alpn.is_empty()
                            && self
                                .handshake_data
                                .as_ref()
                                .and_then(|data| data.protocol.as_deref())
                                == Some(alpn.as_bytes())
                    })
            })
    }

    fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        tracing::trace!(bytes = buf.len(), "quic.tls_handshake_input");
        let result = match self.connection.read(buf) {
            Ok(result) => result,
            Err(error) => {
                self.post_handshake = None;
                self.zero_rtt = None;
                return Err(map_control_error(error));
            }
        };
        if let Some(zero_rtt) = &mut self.zero_rtt {
            zero_rtt.rejected |= self.connection.has_retried();
        }
        let Some(result) = result else {
            return Ok(false);
        };
        self.handshake_data = Some(HandshakeData {
            protocol: result.negotiated_alpn.map(String::into_bytes),
            cipher_suite: result.negotiated_cipher_suite,
        });
        self.peer_transport_parameters = result
            .peer_transport_params
            .as_ref()
            .map(encode_transport_params);
        self.post_handshake = result.post_handshake;
        if let Some(zero_rtt) = &mut self.zero_rtt {
            zero_rtt.accepted = result.early_data_accepted;
            zero_rtt.session_resumed = result.session_resumed;
        }
        tracing::debug!(
            alpn = ?self.handshake_data.as_ref().and_then(|data| data.protocol.as_ref()),
            cipher_suite = ?self.handshake_data.as_ref().and_then(|data| data.cipher_suite),
            early_data_accepted = result.early_data_accepted,
            peer_transport_params = self.peer_transport_parameters.is_some(),
            "quic.tls_handshake_complete"
        );
        Ok(true)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let Some(bytes) = self.peer_transport_parameters.as_ref() else {
            return Ok(None);
        };

        let mut cursor = io::Cursor::new(bytes.as_slice());
        TransportParameters::read(self.side, &mut cursor)
            .map(Some)
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.connection
            .write_handshake(buf)
            .map(|(_, secrets)| keys_from_secrets(&secrets, self.side))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let post = self.post_handshake.as_mut()?;
        let hkdf = post.hkdf_algorithm;
        let aead = post.aead_algorithm;

        // QUIC redefines the key-update label as "quic ku" (RFC 9001 §6.1).
        // This is distinct from the TLS-1.3-over-TCP KeyUpdate label
        // ("traffic upd", RFC 8446 §7.2) used on the TCP path; using the TCP
        // label here would derive keys the peer cannot decrypt.
        let next_local_secret = hkdf_expand_label(
            hkdf,
            &post.client_app_secret,
            "quic ku",
            &[],
            hkdf.hash_len(),
        )
        .ok()?;
        let next_remote_secret = hkdf_expand_label(
            hkdf,
            &post.server_app_secret,
            "quic ku",
            &[],
            hkdf.hash_len(),
        )
        .ok()?;

        let local = packet_key_from_derived(
            derive_packet_keys(&next_local_secret, hkdf, aead).ok()?,
            aead,
        );
        let remote = packet_key_from_derived(
            derive_packet_keys(&next_remote_secret, hkdf, aead).ok()?,
            aead,
        );

        post.client_app_secret = next_local_secret;
        post.server_app_secret = next_remote_secret;

        Some(KeyPair {
            local: Box::new(local),
            remote: Box::new(remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        // RFC 9001 §5.8: verify the Retry Integrity Tag (the trailing 16 bytes
        // of the Retry packet) with AEAD_AES_128_GCM over the Retry pseudo-
        // packet, using QUIC v1's fixed key/nonce. Chrome speaks QUIC v1, so
        // only the v1 constants are needed.
        const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
            0xc8, 0x4e,
        ];
        const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];

        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };

        // Retry pseudo-packet = ODCID length || ODCID || Retry header || Retry
        // body. The last 16 bytes of the body are the integrity tag; everything
        // before it is the AEAD associated data.
        let mut pseudo_packet =
            Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + payload.len());
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let Ok(unbound) = aws_lc_rs::aead::UnboundKey::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &RETRY_INTEGRITY_KEY_V1,
        ) else {
            return false;
        };
        let key = aws_lc_rs::aead::LessSafeKey::new(unbound);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aws_lc_rs::aead::Aad::from(aad), tag)
            .is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // RFC 8446 §7.5 TLS-Exporter:
        //   secret0 = Derive-Secret(exporter_master_secret, label, "")
        //           = HKDF-Expand-Label(ems, label, Hash(""), Hash.length)
        //   output  = HKDF-Expand-Label(secret0, "exporter", Hash(context), len)
        // Only valid once the handshake has produced the exporter master secret.
        let post = self
            .post_handshake
            .as_ref()
            .ok_or(ExportKeyingMaterialError)?;
        let hkdf = post.hkdf_algorithm;
        // TLS exporter labels are ASCII; lktls' HKDF-Expand-Label takes a &str.
        let label = std::str::from_utf8(label).map_err(|_| ExportKeyingMaterialError)?;
        // HKDF-Expand-Label prefixes "tls13 " and encodes the label length in a
        // single byte (RFC 8446 opaque label<7..255>). Reject labels that would
        // overflow that byte rather than silently derive wrong key material.
        if "tls13 ".len() + label.len() > 255 {
            return Err(ExportKeyingMaterialError);
        }

        let empty_hash = hash_for_hkdf(hkdf, &[]);
        let secret0 = hkdf_expand_label(
            hkdf,
            &post.exporter_master_secret,
            label,
            &empty_hash,
            hkdf.hash_len(),
        )
        .map_err(|_| ExportKeyingMaterialError)?;

        let context_hash = hash_for_hkdf(hkdf, context);
        let derived = hkdf_expand_label(hkdf, &secret0, "exporter", &context_hash, output.len())
            .map_err(|_| ExportKeyingMaterialError)?;
        output.copy_from_slice(&derived);
        Ok(())
    }
}

struct LktlsPacketKey {
    aead: Aead,
    algorithm: AeadAlgorithm,
}

impl crypto::PacketKey for LktlsPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let payload_len = buf.len().saturating_sub(header_len + self.tag_len());
        let aad = &buf[..header_len];
        let plaintext = buf[header_len..header_len + payload_len].to_vec();
        let ciphertext = self
            .aead
            .encrypt(packet, aad, &plaintext)
            .expect("packet encryption must succeed");
        buf[header_len..header_len + ciphertext.len()].copy_from_slice(&ciphertext);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plaintext = self
            .aead
            .decrypt(packet, header, payload.as_ref())
            .map_err(|_| CryptoError)?;
        payload.clear();
        payload.extend_from_slice(&plaintext);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        match self.algorithm {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 1u64 << 23,
            AeadAlgorithm::Chacha20Poly1305 => 1u64 << 62,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.algorithm {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 1u64 << 52,
            AeadAlgorithm::Chacha20Poly1305 => 1u64 << 36,
        }
    }
}

enum HpCipher {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
    ChaCha20([u8; 32]),
}

struct LktlsHeaderProtectionKey {
    cipher: HpCipher,
}

impl LktlsHeaderProtectionKey {
    fn new(key: &[u8], algorithm: AeadAlgorithm) -> Self {
        let cipher = match algorithm {
            AeadAlgorithm::Aes128Gcm => {
                HpCipher::Aes128(Box::new(aes::Aes128::new(GenericArray::from_slice(key))))
            }
            AeadAlgorithm::Aes256Gcm => {
                HpCipher::Aes256(Box::new(aes::Aes256::new(GenericArray::from_slice(key))))
            }
            AeadAlgorithm::Chacha20Poly1305 => {
                let mut hp_key = [0u8; 32];
                hp_key.copy_from_slice(key);
                HpCipher::ChaCha20(hp_key)
            }
        };
        Self { cipher }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        match &self.cipher {
            HpCipher::Aes128(cipher) => {
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                [block[0], block[1], block[2], block[3], block[4]]
            }
            HpCipher::Aes256(cipher) => {
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                [block[0], block[1], block[2], block[3], block[4]]
            }
            HpCipher::ChaCha20(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = GenericArray::from_slice(&sample[4..16]);
                let key = GenericArray::from_slice(key);
                let mut cipher = ChaCha20::new(key, nonce);
                cipher.seek(u64::from(counter) * 64);
                let mut mask = [0u8; 5];
                cipher.apply_keystream(&mut mask);
                mask
            }
        }
    }
}

impl crypto::HeaderKey for LktlsHeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = self.mask(sample);
        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        packet[0] ^= mask[0] & bits;
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        for idx in 0..pn_len {
            packet[pn_offset + idx] ^= mask[idx + 1];
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = self.mask(sample);
        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        packet[0] ^= mask[0] & bits;
        for idx in 0..pn_len {
            packet[pn_offset + idx] ^= mask[idx + 1];
        }
    }

    fn sample_size(&self) -> usize {
        16
    }
}

fn keys_from_derived(keys: lktls::crypto::quic::QuicKeys) -> Keys {
    let local_header = Box::new(LktlsHeaderProtectionKey::new(
        &keys.local.hp_key,
        keys.aead_algorithm,
    ));
    let remote_header = Box::new(LktlsHeaderProtectionKey::new(
        &keys.remote.hp_key,
        keys.aead_algorithm,
    ));
    let local_packet = Box::new(packet_key_from_derived(keys.local, keys.aead_algorithm));
    let remote_packet = Box::new(packet_key_from_derived(keys.remote, keys.aead_algorithm));

    Keys {
        header: KeyPair {
            local: local_header,
            remote: remote_header,
        },
        packet: KeyPair {
            local: local_packet,
            remote: remote_packet,
        },
    }
}

fn keys_from_secrets(secrets: &QuicTrafficSecrets, side: Side) -> Keys {
    let client = derive_packet_keys(
        &secrets.client_secret,
        secrets.hkdf_algorithm,
        secrets.aead_algorithm,
    )
    .expect("client packet key derivation must succeed");
    let server = derive_packet_keys(
        &secrets.server_secret,
        secrets.hkdf_algorithm,
        secrets.aead_algorithm,
    )
    .expect("server packet key derivation must succeed");

    let client_header = Box::new(LktlsHeaderProtectionKey::new(
        &client.hp_key,
        secrets.aead_algorithm,
    ));
    let server_header = Box::new(LktlsHeaderProtectionKey::new(
        &server.hp_key,
        secrets.aead_algorithm,
    ));
    let client_packet = Box::new(packet_key_from_derived(client, secrets.aead_algorithm));
    let server_packet = Box::new(packet_key_from_derived(server, secrets.aead_algorithm));

    match side {
        Side::Client => Keys {
            header: KeyPair {
                local: client_header,
                remote: server_header,
            },
            packet: KeyPair {
                local: client_packet,
                remote: server_packet,
            },
        },
        Side::Server => Keys {
            header: KeyPair {
                local: server_header,
                remote: client_header,
            },
            packet: KeyPair {
                local: server_packet,
                remote: client_packet,
            },
        },
    }
}

fn packet_key_from_derived(keys: LktlsPacketKeys, algorithm: AeadAlgorithm) -> LktlsPacketKey {
    LktlsPacketKey {
        aead: Aead::new(algorithm, &keys.key, &keys.iv)
            .expect("derived packet keys must have valid sizes"),
        algorithm,
    }
}

fn ensure_supported_version(version: u32) -> Result<(), ConnectError> {
    match version {
        1 => Ok(()), // QUIC v1 (RFC 9000) — the only version Chrome supports
        _ => Err(ConnectError::UnsupportedVersion),
    }
}

fn map_tls_start_error(server_name: &str, error: TlsError) -> ConnectError {
    match error {
        TlsError::InvalidProfile(message) => {
            ConnectError::InvalidServerName(format!("{server_name}: invalid profile: {message}"))
        }
        TlsError::HandshakeFailure(message) => {
            ConnectError::InvalidServerName(format!("{server_name}: {message}"))
        }
        _ => ConnectError::InvalidServerName(server_name.to_string()),
    }
}

fn map_tls_error(error: TlsError) -> TransportError {
    let alert_code = match &error {
        TlsError::EchRejected { .. } => Some(lktls::error::AlertDescription::EchRequired.as_byte()),
        _ => error.as_alert().map(|alert| alert.description.as_byte()),
    };
    if let Some(alert_code) = alert_code {
        return TransportError {
            code: TransportErrorCode::crypto(alert_code),
            frame: None,
            reason: error.to_string(),
        };
    }

    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: format!("lktls-quic error: {error}"),
    }
}

impl fmt::Debug for LktlsQuicClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LktlsQuicClientConfig")
            .field("port", &self.port)
            .field("profile", &"[ elided ]")
            .finish()
    }
}

#[derive(Clone)]
struct ZeroRttState {
    keys: LktlsPacketKeys,
    aead_algorithm: AeadAlgorithm,
    alpn: Option<String>,
    session_resumed: bool,
    accepted: bool,
    rejected: bool,
}

/// The only `max_early_data_size` a NewSessionTicket may carry over QUIC.
///
/// RFC 9001 §4.6.1: QUIC bounds early data with its own flow control, so the
/// TLS-level byte budget is meaningless and the field is fixed at `0xffffffff`.
/// A client MUST treat any other value as a connection error.
const QUIC_MAX_EARLY_DATA_SIZE: u32 = 0xffff_ffff;

fn map_control_error(error: QuicControlError) -> TransportError {
    let (code, reason) = match error {
        QuicControlError::Tls(error) => return map_tls_error(error),
        QuicControlError::BufferLimit(reason) => {
            (TransportErrorCode::CRYPTO_BUFFER_EXCEEDED, reason)
        }
        other => (TransportErrorCode::PROTOCOL_VIOLATION, other.to_string()),
    };
    TransportError {
        code,
        frame: None,
        reason,
    }
}

fn derive_early_crypto(
    ticket: &SessionTicketData,
    client_hello: &[u8],
) -> Result<ZeroRttState, TlsError> {
    let zero_salt = vec![0u8; ticket.hkdf_algorithm.hash_len()];
    let early_secret = hkdf_extract(ticket.hkdf_algorithm, &zero_salt, &ticket.resumption_psk)?;
    let transcript_hash = hash_for_hkdf(ticket.hkdf_algorithm, client_hello);
    let early_traffic_secret = early_secret.derive_secret("c e traffic", &transcript_hash)?;
    let keys = derive_packet_keys(
        &early_traffic_secret,
        ticket.hkdf_algorithm,
        ticket.aead_algorithm,
    )?;
    tracing::debug!(
        ticket_age_add = ticket.age_add,
        max_early_data = ticket.max_early_data_size,
        client_hello_len = client_hello.len(),
        "quic.tls_zero_rtt_derived"
    );
    Ok(ZeroRttState {
        keys,
        aead_algorithm: ticket.aead_algorithm,
        alpn: ticket.alpn.clone(),
        session_resumed: false,
        accepted: false,
        rejected: false,
    })
}

fn hash_for_hkdf(algorithm: lktls::crypto::hkdf::HkdfAlgorithm, data: &[u8]) -> Vec<u8> {
    let digest_alg = match algorithm {
        lktls::crypto::hkdf::HkdfAlgorithm::Sha256 => &digest::SHA256,
        lktls::crypto::hkdf::HkdfAlgorithm::Sha384 => &digest::SHA384,
    };
    digest::digest(digest_alg, data).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use lktls::connection::QuicPostHandshake;
    use lktls::handshake::driver::{QuicHandshakeOutput, SessionTicketContext};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Once};

    use h3::server;
    use http::{Request, Response, StatusCode};
    use lkh3::connect_h3;
    use lktls::profile::presets;
    use lktls::session_store::AlpsSessionState;
    use quinn::crypto::rustls::QuicServerConfig;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    fn validate_quic_new_session_ticket(message: &[u8]) -> Result<(), TransportError> {
        QuicPostHandshake::new(None)
            .read(message)
            .map_err(map_control_error)
    }

    fn process_post_handshake_messages(
        message: &[u8],
        context: Option<&SessionTicketContext>,
    ) -> Result<usize, TransportError> {
        let context = context.map(|context| SessionTicketContext {
            resumption_master_secret: context.resumption_master_secret.clone(),
            hkdf_algorithm: context.hkdf_algorithm,
            aead_algorithm: context.aead_algorithm,
            cipher_suite: context.cipher_suite,
            alpn: context.alpn.clone(),
            alps: context.alps.clone(),
            peer_transport_parameters: context.peer_transport_parameters.clone(),
            store: context.store.clone(),
            host_key: context.host_key.clone(),
        });
        let mut control = QuicPostHandshake::new(context);
        control.read(message).map_err(map_control_error)?;
        assert!(
            !control.has_pending_message(),
            "complete-message test input"
        );
        Ok(message.len())
    }

    fn ensure_rustls_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn trust_anchor_from_der(
        cert: &CertificateDer<'static>,
    ) -> rustls_pki_types::TrustAnchor<'static> {
        lktls::verify::certchain::parse_trust_anchor_from_der(cert.as_ref()).unwrap()
    }

    #[derive(Debug)]
    struct StreamReuseHandshake {
        early_available: bool,
        early_accepted: Option<bool>,
        reuse_allowed: bool,
        server_resumed: bool,
        finished_prefix_checked: bool,
        alpn: Option<Vec<u8>>,
        cipher_suite: Option<u16>,
    }

    fn stream_reuse_handshake(
        config: Arc<LktlsQuicClientConfig>,
        server_config: Arc<rustls::ServerConfig>,
        corrupt_finished: bool,
    ) -> Result<StreamReuseHandshake, TransportError> {
        let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
        let mut client = ProtoClientConfig::start_session(config, 1, "localhost", &params).unwrap();
        let early_available = client.early_crypto().is_some();
        assert!(!client.early_data_rejection_allows_stream_reuse());
        let mut server = rustls::quic::ServerConnection::new(
            server_config,
            rustls::quic::Version::V1,
            Vec::new(),
        )
        .unwrap();
        let mut finished_prefix_checked = false;
        for _ in 0..64 {
            let mut to_server = Vec::new();
            let client_keys = client.write_handshake(&mut to_server);
            let mut progressed = client_keys.is_some() || !to_server.is_empty();
            if !to_server.is_empty() {
                server.read_hs(&to_server).unwrap();
            }
            let mut to_client = Vec::new();
            let server_keys = server.write_hs(&mut to_client);
            progressed |= server_keys.is_some() || !to_client.is_empty();
            if !to_client.is_empty() {
                if matches!(server_keys, Some(rustls::quic::KeyChange::OneRtt { .. })) {
                    if corrupt_finished {
                        *to_client.last_mut().unwrap() ^= 1;
                    }
                    // EE and a partial Finished cannot authorize stream reuse.
                    let last = to_client.len() - 1;
                    client.read_handshake(&to_client[..last])?;
                    assert!(client.is_handshaking());
                    assert!(!client.early_data_rejection_allows_stream_reuse());
                    finished_prefix_checked = true;
                    let result = client.read_handshake(&to_client[last..]);
                    if result.is_err() {
                        assert!(!client.early_data_rejection_allows_stream_reuse());
                    }
                    result?;
                } else {
                    client.read_handshake(&to_client)?;
                }
            }
            if !progressed {
                assert!(!client.is_handshaking());
                assert!(!server.is_handshaking());
                let data = client
                    .handshake_data()
                    .unwrap()
                    .downcast::<HandshakeData>()
                    .unwrap();
                return Ok(StreamReuseHandshake {
                    early_available,
                    early_accepted: client.early_data_accepted(),
                    reuse_allowed: client.early_data_rejection_allows_stream_reuse(),
                    server_resumed: server.handshake_kind() == Some(rustls::HandshakeKind::Resumed),
                    finished_prefix_checked,
                    alpn: data.protocol,
                    cipher_suite: data.cipher_suite,
                });
            }
        }
        panic!("in-memory TLS exchange did not finish");
    }

    fn stream_reuse_server_config(
        certificate: &CertificateDer<'static>,
        key: &[u8],
        chacha: bool,
        hrr: bool,
    ) -> rustls::ServerConfig {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = vec![if chacha {
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        } else {
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        }];
        if hrr {
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        }
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h3".to_vec()];
        server.max_early_data_size = u32::MAX;
        server
    }

    #[test]
    fn quic_early_rejection_reuse_authority_requires_verified_resumption() {
        ensure_rustls_provider();
        for variant in [
            "reject",
            "accept",
            "full",
            "no_offer",
            "hrr",
            "alpn",
            "cipher_not_resumed",
        ] {
            let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate = CertificateDer::from(cert.cert.der().to_vec());
            let key = cert.signing_key.serialize_der();
            let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
            let client = LktlsQuicClientConfig::new(presets::chrome_155_quic())
                .custom_ca_anchors(Arc::new(vec![trust_anchor_from_der(&certificate)]))
                .session_store(store);
            let server = stream_reuse_server_config(&certificate, &key, false, false);
            let warm =
                stream_reuse_handshake(Arc::new(client.clone()), Arc::new(server.clone()), false)
                    .unwrap();
            assert!(!warm.early_available && !warm.server_resumed && !warm.reuse_allowed);

            let mut resumed_server = stream_reuse_server_config(
                &certificate,
                &key,
                variant == "cipher_not_resumed",
                variant == "hrr",
            );
            if variant != "full" {
                resumed_server.session_storage = server.session_storage.clone();
            }
            if variant != "accept" {
                resumed_server.max_early_data_size = 0;
            }
            let mut client = client;
            if variant == "no_offer" {
                client = client
                    .with_profile(presets::chrome_144())
                    .alpn_protocols(vec!["h3".into()]);
            }
            if variant == "alpn" {
                client = client.alpn_protocols(vec!["h3".into(), "hq-test".into()]);
                resumed_server.alpn_protocols = vec![b"hq-test".to_vec()];
            }
            let result =
                stream_reuse_handshake(Arc::new(client), Arc::new(resumed_server), false).unwrap();
            assert_eq!(
                result.early_available,
                variant != "no_offer",
                "{variant}: {result:?}"
            );
            assert_eq!(
                result.server_resumed,
                !matches!(variant, "full" | "cipher_not_resumed"),
                "{variant}: {result:?}"
            );
            assert_eq!(
                result.early_accepted,
                (variant != "no_offer").then_some(variant == "accept"),
                "{variant}: {result:?}"
            );
            assert_eq!(
                result.reuse_allowed,
                variant == "reject",
                "{variant}: {result:?}"
            );
            assert!(result.finished_prefix_checked, "{variant}: {result:?}");
            assert_eq!(
                result.alpn.as_deref(),
                Some(if variant == "alpn" {
                    &b"hq-test"[..]
                } else {
                    &b"h3"[..]
                })
            );
            assert_eq!(
                result.cipher_suite,
                Some(if variant == "cipher_not_resumed" {
                    0x1303
                } else {
                    0x1301
                })
            );
        }
    }

    #[test]
    fn quic_cached_sessions_cannot_bypass_changed_authentication_context() {
        for insecure in [false, true] {
            let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate = cert.cert.der().clone();
            let key = cert.signing_key.serialize_der();
            let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
            let mut client =
                LktlsQuicClientConfig::new(presets::chrome_155_quic()).session_store(store);
            if insecure {
                client = client.verification_policy(VerificationPolicy::Insecure);
            } else {
                client =
                    client.custom_ca_anchors(Arc::new(vec![trust_anchor_from_der(&certificate)]));
            }
            let server = Arc::new(stream_reuse_server_config(&certificate, &key, false, false));
            let warm =
                stream_reuse_handshake(Arc::new(client.clone()), server.clone(), false).unwrap();
            assert!(!warm.server_resumed);
            client = client.verification_policy(VerificationPolicy::Strict);
            client.template = client.template.custom_ca_anchors(None);
            let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
            let session =
                ProtoClientConfig::start_session(Arc::new(client.clone()), 1, "localhost", &params)
                    .unwrap();
            assert!(session.early_crypto().is_none());
            assert!(stream_reuse_handshake(Arc::new(client), server, false).is_err());
        }
    }

    #[test]
    fn quic_early_rejection_reuse_authority_rejects_invalid_finished() {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = CertificateDer::from(cert.cert.der().to_vec());
        let key = cert.signing_key.serialize_der();
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let client = Arc::new(
            LktlsQuicClientConfig::new(presets::chrome_155_quic())
                .custom_ca_anchors(Arc::new(vec![trust_anchor_from_der(&certificate)]))
                .session_store(store),
        );
        let mut server = stream_reuse_server_config(&certificate, &key, false, false);
        let warm = stream_reuse_handshake(client.clone(), Arc::new(server.clone()), false).unwrap();
        assert!(!warm.early_available);
        server.max_early_data_size = 0;
        let error = stream_reuse_handshake(client, Arc::new(server), true)
            .expect_err("a corrupted server Finished must not complete the reuse authority");
        assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
        assert!(error
            .reason
            .contains("server Finished verify_data mismatch"));
    }

    #[derive(Debug, Default)]
    struct RejectionTicketCounter(std::sync::atomic::AtomicUsize);

    impl SessionStore for RejectionTicketCounter {
        fn store(&self, _host: &str, _ticket: SessionTicketData) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn take(&self, _host: &str) -> Option<SessionTicketData> {
            None
        }
    }

    fn local_rejection_ech_config(public_name: &str) -> Vec<u8> {
        let mut contents = vec![42, 0, 32, 0, 32];
        contents.extend_from_slice(&[0x42; 32]);
        contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 64]);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&[0, 0]);
        let mut config = vec![0xfe, 0x0d];
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = (config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&config);
        list
    }

    #[test]
    fn ech_rejected_transport_error_preserves_retry_config_diagnostics() {
        let error = map_tls_error(TlsError::EchRejected {
            retry_configs: Some(vec![1, 2, 3]),
        });
        assert_eq!(error.code, TransportErrorCode::crypto(121));
        assert!(error.reason.contains("retry_configs: 3 bytes"));
        assert!(error.frame.is_none());
        let other = map_tls_error(TlsError::HandshakeFailure("synthetic failure".into()));
        assert_eq!(other.code, TransportErrorCode::PROTOCOL_VIOLATION);
    }

    #[tokio::test]
    async fn quic_ech_rejection_maps_ech_required_at_both_peers() {
        use std::time::Duration;

        tokio::time::timeout(Duration::from_secs(15), async {
            ensure_rustls_provider();
            let public_name = "public.quic-ech-test.invalid";
            for force_hrr in [false, true] {
                let cert = generate_simple_self_signed(vec![public_name.into()]).unwrap();
                let cert_der = CertificateDer::from(cert.cert.der().to_vec());
                let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
                let mut provider = rustls::crypto::ring::default_provider();
                if force_hrr { provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1]; }
                let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
                    .with_no_client_auth().with_single_cert(vec![cert_der.clone()], key).unwrap();
                tls.alpn_protocols = vec![b"h3".to_vec()];
                let port = std::env::var("QUIC_REJECTION_CAPTURE_PORT").ok().map(|value| {
                    let base: u16 = value.parse().unwrap();
                    assert!((1024..=65534).contains(&base));
                    base + u16::from(force_hrr)
                }).unwrap_or(0);
                let server = Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(
                    QuicServerConfig::try_from(tls).unwrap(),
                )), SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))).unwrap();
                let addr = server.local_addr().unwrap();
                let peer = tokio::spawn({
                    let server = server.clone();
                    async move {
                        match server.accept().await.unwrap().await {
                            Ok(connection) => connection.closed().await,
                            Err(error) => error,
                        }
                    }
                });
                let tickets = Arc::new(RejectionTicketCounter::default());
                let mut profile = presets::chrome_155();
                profile.alpn_protocols = vec!["h3".into()];
                let mut crypto = LktlsQuicClientConfig::new(profile)
                    .custom_ca_anchors(Arc::new(vec![trust_anchor_from_der(&cert_der)]))
                    .session_store(tickets.clone()).port(addr.port())
                    .ech_config(local_rejection_ech_config(public_name));
                if let Some(path) = std::env::var_os("FINGERPRINT_CAPTURE_KEYLOG") {
                    use std::io::Write;
                    let path = std::path::PathBuf::from(path);
                    assert!(path.is_absolute());
                    let file = std::sync::Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap());
                    crypto = crypto.keylog(Arc::new(move |line| { writeln!(file.lock().unwrap(), "{line}").unwrap(); }));
                }
                let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                client.set_default_client_config(crypto.into_quinn());
                let error = client.connect(addr, "secret.quic-ech-test.invalid").unwrap().await.expect_err("ECH rejection cannot establish a usable connection");
                let remote = peer.await.unwrap();
                let expected = TransportErrorCode::crypto(121);
                assert!(matches!(&error, quinn::ConnectionError::TransportError(error) if error.code == expected), "client HRR={force_hrr}: {error:?}");
                assert!(matches!(&remote, quinn::ConnectionError::ConnectionClosed(close) if close.error_code == expected), "peer HRR={force_hrr}: {remote:?}");
                assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
                println!("QUIC ECH rejection HRR={force_hrr}: both peers CRYPTO_ERROR 0x179, no ticket stores");
                client.close(0u32.into(), b"test complete");
                server.close(0u32.into(), b"test complete");
                client.wait_idle().await;
                server.wait_idle().await;
            }
        }).await.expect("local QUIC ECH rejection timed out");
    }

    fn build_hrr(session_id: &[u8], cipher_suite: u16, selected_group: u16) -> Vec<u8> {
        let extensions = [
            0x00,
            0x2b,
            0x00,
            0x02,
            0x03,
            0x04,
            0x00,
            0x33,
            0x00,
            0x02,
            (selected_group >> 8) as u8,
            selected_group as u8,
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&lktls::handshake::server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len() as u32;
        let mut message = vec![
            0x02,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        message.extend_from_slice(&body);
        message
    }

    #[tokio::test]
    async fn quic_incompatible_alpn_peer_reports_no_application_protocol() {
        use std::time::Duration;

        tokio::time::timeout(Duration::from_secs(15), async {
            ensure_rustls_provider();
            for force_hrr in [false, true] {
                let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let cert_der = CertificateDer::from(cert.cert.der().to_vec());
                let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
                let mut provider = rustls::crypto::ring::default_provider();
                if force_hrr { provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1]; }
                let tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
                    .with_no_client_auth().with_single_cert(vec![cert_der.clone()], key).unwrap();
                let server = Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(
                    QuicServerConfig::try_from(tls).unwrap(),
                )), "127.0.0.1:0".parse().unwrap()).unwrap();
                let addr = server.local_addr().unwrap();
                let peer = tokio::spawn({
                    let server = server.clone();
                    async move {
                        match server.accept().await.unwrap().await {
                            Ok(connection) => connection.closed().await,
                            Err(error) => error,
                        }
                    }
                });
                let tickets = Arc::new(RejectionTicketCounter::default());
                let mut profile = presets::chrome_155();
                profile.alpn_protocols = vec!["h3".into()];
                let crypto = LktlsQuicClientConfig::new(profile)
                    .custom_ca_anchors(Arc::new(vec![trust_anchor_from_der(&cert_der)]))
                    .session_store(tickets.clone()).port(addr.port());
                let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                client.set_default_client_config(crypto.into_quinn());
                let error = client.connect(addr, "localhost").unwrap().await
                    .expect_err("QUIC must not establish when offered ALPN goes unnegotiated");
                let remote = peer.await.unwrap();
                let expected = TransportErrorCode::crypto(120);
                assert!(matches!(&error, quinn::ConnectionError::ConnectionClosed(close) if close.error_code == expected), "client HRR={force_hrr}: {error:?}");
                assert!(matches!(&remote, quinn::ConnectionError::TransportError(error) if error.code == expected), "peer HRR={force_hrr}: {remote:?}");
                assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
                client.close(0u32.into(), b"test complete");
                server.close(0u32.into(), b"test complete");
                client.wait_idle().await;
                server.wait_idle().await;
            }
        }).await.expect("local QUIC ALPN test timed out");
    }

    #[test]
    fn quic_session_checks_actual_version_offer_before_handshake_keys_or_retry() {
        use lktls::crypto::kx::{generate_key_pair, KxGroup};
        use lktls::profile::types::ExtensionSource;

        for retry in [false, true] {
            // None omits supported_versions; raw bytes can replace the profile offer.
            for offer in [Some("020303"), None, Some("020304")] {
                let tickets = Arc::new(RejectionTicketCounter::default());
                let mut profile = presets::chrome_155();
                if let Some(data) = offer {
                    profile
                        .extensions
                        .iter_mut()
                        .find(|extension| extension.extension_type == 43)
                        .unwrap()
                        .source = ExtensionSource::RawBytes { data: data.into() };
                } else {
                    profile
                        .extensions
                        .retain(|extension| extension.extension_type != 43);
                }
                let config =
                    Arc::new(LktlsQuicClientConfig::new(profile).session_store(tickets.clone()));
                let parameters = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
                let mut session = config.start_session(1, "localhost", &parameters).unwrap();
                let mut hello = Vec::new();
                assert!(session.write_handshake(&mut hello).is_none());
                let observed = lkprofile::parse_client_hello(&hello).unwrap();
                let versions = observed
                    .extensions
                    .iter()
                    .find(|extension| extension.extension_type == 43);
                if let Some(data) = offer {
                    assert_eq!(
                        versions.unwrap().data,
                        [2, 3, if data == "020304" { 4 } else { 3 }]
                    );
                } else {
                    assert!(versions.is_none());
                }

                let mut extensions = vec![0, 43, 0, 2, 3, 4];
                let key_share = if retry {
                    vec![0, 24]
                } else {
                    let server_key = generate_key_pair(KxGroup::X25519).unwrap();
                    let mut share = vec![0, 29];
                    share.extend_from_slice(&(server_key.public_key.len() as u16).to_be_bytes());
                    share.extend_from_slice(&server_key.public_key);
                    share
                };
                extensions.extend_from_slice(&[0, 51]);
                extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&key_share);
                let mut body = vec![3, 3];
                body.extend_from_slice(if retry {
                    &lktls::handshake::server_hello::HRR_RANDOM
                } else {
                    &[0x55; 32]
                });
                body.extend_from_slice(&[0, 0x13, 1, 0]);
                body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
                body.extend_from_slice(&extensions);
                let mut message = vec![2, 0, 0, body.len() as u8];
                message.extend_from_slice(&body);

                if offer == Some("020304") {
                    assert!(!session.read_handshake(&message).unwrap());
                    let mut outbound = Vec::new();
                    let keys = session.write_handshake(&mut outbound);
                    assert_eq!(keys.is_some(), !retry);
                    assert_eq!(!outbound.is_empty(), retry);
                } else {
                    let error = session
                        .read_handshake(&message)
                        .expect_err("TLS 1.3 was absent from the emitted offer");
                    assert_eq!(
                        error.code,
                        TransportErrorCode::crypto(if offer.is_some() { 47 } else { 110 })
                    );
                    let mut outbound = Vec::new();
                    assert!(session.write_handshake(&mut outbound).is_none());
                    assert!(outbound.is_empty(), "no CH2 after an unoffered version");
                    assert!(session.handshake_data().is_none());
                }
                assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[test]
    fn quic_session_rejects_missing_or_unoffered_server_alpn_before_application_keys() {
        use lktls::crypto::kx::{generate_key_pair, KxGroup};

        for selected in [None, Some(b"h2".as_slice())] {
            let tickets = Arc::new(RejectionTicketCounter::default());
            let mut profile = presets::chrome_155();
            profile.alpn_protocols = vec!["h3".into()];
            let config =
                Arc::new(LktlsQuicClientConfig::new(profile).session_store(tickets.clone()));
            let parameters = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
            let mut session = config.start_session(1, "localhost", &parameters).unwrap();
            let mut hello = Vec::new();
            assert!(session.write_handshake(&mut hello).is_none());
            let server_key = generate_key_pair(KxGroup::X25519).unwrap();
            let mut extensions = vec![0, 43, 0, 2, 3, 4];
            let mut key_share = vec![0, 29];
            key_share.extend_from_slice(&(server_key.public_key.len() as u16).to_be_bytes());
            key_share.extend_from_slice(&server_key.public_key);
            extensions.extend_from_slice(&[0, 51]);
            extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&key_share);
            let mut body = vec![3, 3];
            body.extend_from_slice(&[0x55; 32]);
            body.extend_from_slice(&[0, 0x13, 1, 0]);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            let mut message = vec![2, 0, 0, body.len() as u8];
            message.extend_from_slice(&body);
            assert!(!session.read_handshake(&message).unwrap());
            assert!(
                session.write_handshake(&mut Vec::new()).is_some(),
                "only handshake keys so far"
            );
            let mut extensions = vec![0, 57, 0, 0];
            if let Some(protocol) = selected {
                extensions.extend_from_slice(&[0, 16]);
                extensions.extend_from_slice(&((3 + protocol.len()) as u16).to_be_bytes());
                extensions.extend_from_slice(&((1 + protocol.len()) as u16).to_be_bytes());
                extensions.push(protocol.len() as u8);
                extensions.extend_from_slice(protocol);
            }
            let mut message = vec![8, 0, 0, (2 + extensions.len()) as u8];
            message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            message.extend_from_slice(&extensions);
            let error = session
                .read_handshake(&message)
                .expect_err("malformed peer ALPN must close locally");
            assert_eq!(
                error.code,
                TransportErrorCode::crypto(if selected.is_some() { 47 } else { 120 })
            );
            assert!(session.is_handshaking());
            assert!(session.handshake_data().is_none());
            assert!(
                session.write_handshake(&mut Vec::new()).is_none(),
                "no application keys"
            );
            assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn lktls_quic_hrr_with_p384_server_and_h3_request() {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));

        let server = Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let mut h3_conn =
                    server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                if let Some(resolver) = h3_conn.accept().await.unwrap() {
                    let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    stream.send_response(response).await.unwrap();
                    stream.finish().await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        });

        let anchor = trust_anchor_from_der(&cert_der);
        let client_crypto = LktlsQuicClientConfig::new({
            let mut profile = presets::chrome_144();
            assert!(profile.supported_groups.contains(&0x0018));
            assert!(!profile.key_share_curves.contains(&0x0018));
            profile.alpn_protocols = vec!["h3".to_string()];
            profile
        })
        .custom_ca_anchors(Arc::new(vec![anchor]))
        .port(server_addr.port());
        let mut endpoint =
            Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        endpoint.set_default_client_config(client_crypto.into_quinn());

        let quic_conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = connect_h3(quic_conn, &lkh3::chrome_h3()).await.unwrap();
        let mut sender = connection.clone_sender();

        let request = Request::builder()
            .uri("https://localhost/test")
            .body(None)
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        server_task.await.unwrap();
        endpoint.wait_idle().await;
        server.wait_idle().await;
    }

    #[tokio::test]
    async fn lktls_quic_enables_zero_rtt_after_ticket_is_stored() {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        server_tls.max_early_data_size = u32::MAX;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));

        let server = Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                for _ in 0..2 {
                    let incoming = server.accept().await.unwrap();
                    let conn = incoming.await.unwrap();
                    let mut h3_conn =
                        server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                            .await
                            .unwrap();

                    if let Some(resolver) = h3_conn.accept().await.unwrap() {
                        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        stream.send_response(response).await.unwrap();
                        stream.finish().await.unwrap();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        });

        let anchor = trust_anchor_from_der(&cert_der);
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let client_crypto = LktlsQuicClientConfig::new(presets::chrome_155_quic())
            .custom_ca_anchors(Arc::new(vec![anchor]))
            .session_store(store.clone())
            .port(server_addr.port());

        let mut endpoint =
            Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        endpoint.set_default_client_config(client_crypto.clone().into_quinn());

        let quic_conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = connect_h3(quic_conn, &lkh3::chrome_h3()).await.unwrap();
        let mut sender = connection.clone_sender();

        let request = Request::builder()
            .uri("https://localhost/zerortt")
            .body(None)
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let connecting = endpoint.connect(server_addr, "localhost").unwrap();
        let (connection, accepted) = connecting
            .into_0rtt()
            .expect("expected session ticket to make 0-RTT available");
        let stream = connection.open_uni().await.expect("0-rtt stream open");
        drop(stream);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), accepted)
                .await
                .expect("0-RTT handshake completion"),
            "the compatible QUIC profile must be accepted for 0-RTT"
        );

        server_task.abort();
        endpoint.wait_idle().await;
        server.wait_idle().await;
    }

    #[test]
    fn derive_early_crypto_from_ticket_and_client_hello() {
        let ticket = SessionTicketData {
            ticket: vec![1, 2, 3],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            used_extended_master_secret: None,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn: Some("h3".into()),
            alps: Default::default(),
            hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 16_384,
            peer_transport_parameters: Some(vec![0x01, 0x00]),
        };

        let state = derive_early_crypto(&ticket, b"client hello bytes").unwrap();
        assert_eq!(state.aead_algorithm, AeadAlgorithm::Aes128Gcm);
        assert_eq!(state.keys.key.len(), 16);
        assert_eq!(state.keys.iv.len(), 12);
        assert_eq!(state.keys.hp_key.len(), 16);
        assert!(!state.accepted);
        assert!(!state.rejected);
    }

    // ====================================================================
    // RFC 9001 §4.6.1 — `max_early_data_size` over QUIC is 0xffffffff or
    // nothing
    // ====================================================================

    /// Builds a NewSessionTicket handshake message whose extension block is
    /// `extensions` verbatim, so a test can hand the RFC 9001 §4.6.1 check
    /// exactly the `early_data` extension it wants to exercise.
    fn build_new_session_ticket(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&3600u32.to_be_bytes()); // ticket_lifetime
        body.extend_from_slice(&0u32.to_be_bytes()); // ticket_age_add
        body.push(4); // ticket_nonce length
        body.extend_from_slice(&[0, 0, 0, 1]); // ticket_nonce
        body.extend_from_slice(&3u16.to_be_bytes()); // ticket length
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // ticket
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let body_len = body.len() as u32;
        let mut message = vec![
            0x04,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        message.extend_from_slice(&body);
        message
    }

    /// `early_data` (0x002a) carrying `max_early_data_size`.
    fn early_data_extension(max_early_data_size: u32) -> Vec<u8> {
        let mut ext = vec![0x00, 0x2a, 0x00, 0x04];
        ext.extend_from_slice(&max_early_data_size.to_be_bytes());
        ext
    }

    /// A server that issues a QUIC session ticket whose `early_data` extension
    /// carries anything but 0xffffffff has violated RFC 9001 §4.6.1, and the
    /// client MUST fail the connection with PROTOCOL_VIOLATION rather than
    /// quietly keeping the ticket.
    #[test]
    fn new_session_ticket_early_data_size_must_be_0xffffffff() {
        assert_eq!(
            validate_quic_new_session_ticket(&build_new_session_ticket(&early_data_extension(
                QUIC_MAX_EARLY_DATA_SIZE
            ))),
            Ok(()),
            "0xffffffff is the value QUIC mandates and must be accepted",
        );
        assert_eq!(
            validate_quic_new_session_ticket(&build_new_session_ticket(&[])),
            Ok(()),
            "a ticket with no early_data extension is legal — it just forbids 0-RTT",
        );

        for bad in [0u32, 1, 16_384, 0xffff_fffe] {
            let err = validate_quic_new_session_ticket(&build_new_session_ticket(
                &early_data_extension(bad),
            ))
            .expect_err("a non-0xffffffff max_early_data_size must fail the connection");
            assert_eq!(
                err.code,
                TransportErrorCode::PROTOCOL_VIOLATION,
                "RFC 9001 §4.6.1 mandates PROTOCOL_VIOLATION for max_early_data_size {bad:#x}",
            );
        }

        // Present but not a 4-byte value: also not the mandated extension.
        let malformed = validate_quic_new_session_ticket(&build_new_session_ticket(&[
            0x00, 0x2a, 0x00, 0x02, 0xff, 0xff,
        ]))
        .expect_err("a malformed early_data extension must fail the connection");
        assert_eq!(malformed.code, TransportErrorCode::crypto(50));
    }

    fn ticket_context(store: Arc<dyn SessionStore>) -> SessionTicketContext {
        SessionTicketContext {
            resumption_master_secret: vec![0x5A; 32],
            hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            cipher_suite: 0x1301,
            alpn: Some("h3".into()),
            alps: AlpsSessionState::NotNegotiated,
            peer_transport_parameters: Some(vec![0x01, 0x00]),
            store,
            host_key: "example.com:443".to_string(),
        }
    }

    /// The post-handshake path must apply the §4.6.1 check where the ticket
    /// arrives: an illegal `early_data` fails the connection *and* the ticket
    /// never reaches the store, so no later connection can resume on it.
    #[test]
    fn post_handshake_ticket_with_illegal_early_data_fails_the_connection() {
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let ctx = ticket_context(store.clone());

        let bad = build_new_session_ticket(&early_data_extension(16_384));
        let err = process_post_handshake_messages(&bad, Some(&ctx))
            .expect_err("an illegal early_data must fail the connection");
        assert_eq!(err.code, TransportErrorCode::PROTOCOL_VIOLATION);
        assert!(
            store.take("example.com:443").is_none(),
            "a ticket that fails RFC 9001 §4.6.1 must not be stored",
        );

        let good = build_new_session_ticket(&early_data_extension(QUIC_MAX_EARLY_DATA_SIZE));
        assert_eq!(
            process_post_handshake_messages(&good, Some(&ctx)),
            Ok(good.len()),
            "a conforming ticket must be consumed without error",
        );
        assert!(
            store.take("example.com:443").is_some(),
            "a conforming ticket must still be stored",
        );
    }

    fn established_quic_session(ctx: Option<SessionTicketContext>) -> LktlsQuicSession {
        LktlsQuicSession {
            side: Side::Client,
            connection: QuicClientConnection::from_post_handshake(QuicPostHandshake::new(ctx)),
            handshake_data: None,
            peer_transport_parameters: None,
            post_handshake: None,
            zero_rtt: None,
        }
    }

    #[test]
    fn quic_post_handshake_rejects_tls_key_update() {
        let store = Arc::new(RejectionTicketCounter::default());
        let ctx = ticket_context(store.clone());
        let error = process_post_handshake_messages(&[0x18, 0, 0, 1, 0], Some(&ctx))
            .expect_err("QUIC replaces TLS KeyUpdate with its own key phase update");
        assert_eq!(error.code, TransportErrorCode::crypto(10));
        assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn quic_post_handshake_rejects_non_ticket_messages() {
        let store = Arc::new(RejectionTicketCounter::default());
        let ctx = ticket_context(store.clone());
        for kind in [0x00, 0x05, 0x14] {
            let mut message = vec![kind, 0, 0, 0];
            if kind == 0x14 {
                message[3] = 32;
                message.extend_from_slice(&[0; 32]);
            }
            let error = process_post_handshake_messages(&message, Some(&ctx))
                .expect_err("only NewSessionTicket is valid for this QUIC client state");
            assert_eq!(error.code, TransportErrorCode::crypto(10), "type={kind:#x}");
        }
        assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn quic_post_handshake_rejects_fragmented_key_update_without_ticket_storage() {
        let mut session = established_quic_session(None);
        let error = match session.read_handshake(&[0x18, 0]) {
            Err(error) => error,
            Ok(_) => session
                .read_handshake(&[0, 1, 0])
                .expect_err("disabling ticket storage must not disable CRYPTO message validation"),
        };
        assert_eq!(error.code, TransportErrorCode::crypto(10));
    }

    #[test]
    fn quic_post_handshake_overflow_cannot_restart_message_framing() {
        let store = Arc::new(RejectionTicketCounter::default());
        let mut session = established_quic_session(Some(ticket_context(store.clone())));
        let mut oversized_fragment = vec![0; 256 * 1024 + 1];
        oversized_fragment[..4].copy_from_slice(&[0x04, 0x08, 0, 0]);
        match session.read_handshake(&oversized_fragment) {
            Err(error) => assert_eq!(error.code, TransportErrorCode::CRYPTO_BUFFER_EXCEEDED),
            Ok(_) => {
                // An endpoint may permanently ignore further CRYPTO after overflow,
                // but must not interpret a continuation as a new handshake message.
                let continuation = build_new_session_ticket(&[]);
                assert_eq!(session.read_handshake(&continuation), Ok(false));
            }
        }
        assert_eq!(
            store.0.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "overflow must not turn later bytes inside an unfinished message into a ticket"
        );
    }

    #[test]
    fn quic_post_handshake_preserves_fragmented_and_coalesced_tickets() {
        let ticket = build_new_session_ticket(&[]);
        for split in [1, 3, 4, 11, ticket.len() - 1] {
            let store = Arc::new(RejectionTicketCounter::default());
            let mut session = established_quic_session(Some(ticket_context(store.clone())));
            assert_eq!(session.read_handshake(&ticket[..split]), Ok(false));
            assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            let mut rest = ticket[split..].to_vec();
            rest.extend_from_slice(&ticket);
            assert_eq!(session.read_handshake(&rest), Ok(false));
            assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert!(!session.connection.has_pending_message());
        }
    }

    #[test]
    fn quic_post_handshake_accepts_valid_tickets_without_storage() {
        let ticket = build_new_session_ticket(&[]);
        let mut session = established_quic_session(None);
        for byte in ticket {
            assert_eq!(session.read_handshake(&[byte]), Ok(false));
        }
        assert!(!session.connection.has_pending_message());
    }

    #[test]
    fn quic_post_handshake_validates_ticket_allowance_without_storage() {
        let ticket = build_new_session_ticket(&early_data_extension(16_384));
        let mut session = established_quic_session(None);
        let error = session
            .read_handshake(&ticket)
            .expect_err("ticket storage must not gate QUIC ticket validation");
        assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
    }

    #[test]
    fn quic_post_handshake_consumes_large_coalesced_ticket_batch() {
        let ticket = build_new_session_ticket(&[]);
        let count = (256 * 1024) / ticket.len() + 1;
        let store = Arc::new(RejectionTicketCounter::default());
        let mut session = established_quic_session(Some(ticket_context(store.clone())));
        assert_eq!(session.read_handshake(&ticket.repeat(count)), Ok(false));
        assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), count);
        assert!(!session.connection.has_pending_message());
    }

    fn nst_structure_body(nonce: &[u8], ticket: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&3600u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.push(nonce.len() as u8);
        body.extend_from_slice(nonce);
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    fn nst_structure_message(body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut message = vec![0x04, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        message.extend_from_slice(body);
        message
    }

    fn nst_structure_observe(
        message: &[u8],
        storage: bool,
    ) -> (Result<bool, TransportError>, Vec<u32>) {
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let mut session = established_quic_session(storage.then(|| ticket_context(store.clone())));
        let result = session.read_handshake(message);
        let stored = std::iter::from_fn(|| store.take("example.com:443"))
            .map(|ticket| ticket.max_early_data_size)
            .collect();
        (result, stored)
    }

    fn nst_structure_failures(cases: &[(&str, Vec<u8>)], alert: u8) -> Vec<String> {
        let mut failures = Vec::new();
        for (name, message) in cases {
            for storage in [false, true] {
                let (result, stored) = nst_structure_observe(message, storage);
                eprintln!(
                    "NST {name}: storage={storage}, result={result:?}, stored_early_data={stored:?}"
                );
                if !matches!(&result, Err(error) if error.code == TransportErrorCode::crypto(alert))
                    || !stored.is_empty()
                {
                    failures.push(format!(
                        "{name}, storage={storage}: result={result:?}, stored={stored:?}"
                    ));
                }
            }
        }
        failures
    }

    #[test]
    fn quic_nst_structure_rejects_missing_and_truncated_fields() {
        let body = nst_structure_body(&[0; 4], &[1, 2, 3], &[]);
        let cases = [
            ("empty_body", nst_structure_message(&[])),
            ("short_lifetime", nst_structure_message(&body[..2])),
            ("missing_nonce_length", nst_structure_message(&body[..8])),
            ("truncated_nonce", nst_structure_message(&body[..10])),
            (
                "truncated_ticket_length",
                nst_structure_message(&body[..14]),
            ),
            ("truncated_ticket", nst_structure_message(&body[..16])),
            (
                "missing_extensions_length",
                nst_structure_message(&body[..18]),
            ),
            (
                "empty_ticket",
                nst_structure_message(&nst_structure_body(&[], &[], &[])),
            ),
        ];
        let failures = nst_structure_failures(&cases, 50);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn quic_nst_structure_rejects_extension_length_mismatches() {
        let body = nst_structure_body(&[0; 4], &[1, 2, 3], &[]);
        let mut oversized = body.clone();
        oversized[19] = 1;
        let mut undersized = nst_structure_body(&[0; 4], &[1, 2, 3], &[0xbe, 0xef, 0, 1, 7]);
        undersized[19] = 4;
        let mut trailing = body;
        trailing.push(7);
        let mut cases = vec![
            (
                "extensions_length_exceeds_body",
                nst_structure_message(&oversized),
            ),
            (
                "extensions_length_leaves_byte",
                nst_structure_message(&undersized),
            ),
            (
                "trailing_after_empty_extensions",
                nst_structure_message(&trailing),
            ),
        ];
        for (name, extensions) in [
            ("partial_extension_type", vec![0xbe]),
            ("missing_extension_length", vec![0xbe, 0xef]),
            ("partial_extension_length", vec![0xbe, 0xef, 0]),
            ("truncated_unknown_extension", vec![0xbe, 0xef, 0, 2, 7]),
            (
                "truncated_early_data_payload",
                vec![0, 42, 0, 4, 0xff, 0xff],
            ),
        ] {
            cases.push((name, build_new_session_ticket(&extensions)));
        }
        let failures = nst_structure_failures(&cases, 50);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn quic_nst_structure_rejects_duplicate_early_data_in_both_orders() {
        let mut cases = Vec::new();
        for (name, first, second) in [
            ("max_then_zero", QUIC_MAX_EARLY_DATA_SIZE, 0),
            ("zero_then_max", 0, QUIC_MAX_EARLY_DATA_SIZE),
            (
                "max_then_max",
                QUIC_MAX_EARLY_DATA_SIZE,
                QUIC_MAX_EARLY_DATA_SIZE,
            ),
        ] {
            let mut extensions = early_data_extension(first);
            extensions.extend_from_slice(&early_data_extension(second));
            cases.push((name, build_new_session_ticket(&extensions)));
        }
        let failures = nst_structure_failures(&cases, 47);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn quic_nst_structure_reports_decode_error_for_non_u32_early_data() {
        let mut cases = Vec::new();
        for (name, len) in [
            ("empty", 0),
            ("one", 1),
            ("two", 2),
            ("three", 3),
            ("five", 5),
        ] {
            let mut extensions = vec![0, 42, 0, len];
            extensions.extend(std::iter::repeat_n(0xff, len as usize));
            cases.push((name, build_new_session_ticket(&extensions)));
        }
        let failures = nst_structure_failures(&cases, 50);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn quic_nst_structure_stops_before_a_later_coalesced_ticket() {
        let body = nst_structure_body(&[0; 4], &[1, 2, 3], &[]);
        let valid = build_new_session_ticket(&[]);
        let mut cases = Vec::new();
        for (name, malformed) in [
            ("empty_before_valid", nst_structure_message(&[])),
            (
                "missing_extensions_before_valid",
                nst_structure_message(&body[..18]),
            ),
        ] {
            let mut batch = malformed;
            batch.extend_from_slice(&valid);
            cases.push((name, batch));
        }
        let failures = nst_structure_failures(&cases, 50);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn quic_nst_structure_retains_boringssl_unknown_extension_controls() {
        let unknown = vec![0xbe, 0xef, 0, 1, 7];
        let mut duplicate_unknown = unknown.clone();
        duplicate_unknown.extend_from_slice(&[0xbe, 0xef, 0, 0]);
        let mut unknown_and_early = unknown.clone();
        unknown_and_early.extend_from_slice(&early_data_extension(QUIC_MAX_EARLY_DATA_SIZE));
        for (name, extensions, expected_early) in [
            ("empty_nonce_and_extensions", Vec::new(), 0),
            ("unknown_extension", unknown, 0),
            ("ignored_duplicate_unknown", duplicate_unknown, 0),
            (
                "unknown_with_early_data",
                unknown_and_early,
                QUIC_MAX_EARLY_DATA_SIZE,
            ),
        ] {
            let message = nst_structure_message(&nst_structure_body(&[], &[1], &extensions));
            for storage in [false, true] {
                let (result, stored) = nst_structure_observe(&message, storage);
                assert_eq!(result, Ok(false), "{name}, storage={storage}");
                assert_eq!(
                    stored,
                    if storage {
                        vec![expected_early]
                    } else {
                        Vec::new()
                    },
                    "{name}, storage={storage}"
                );
            }
        }
    }

    #[test]
    fn quic_nst_structure_retains_fragmented_valid_extensions() {
        let mut extensions = vec![0xbe, 0xef, 0, 1, 7];
        extensions.extend_from_slice(&early_data_extension(QUIC_MAX_EARLY_DATA_SIZE));
        let message = nst_structure_message(&nst_structure_body(&[], &[1], &extensions));
        for storage in [false, true] {
            let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
            let mut session =
                established_quic_session(storage.then(|| ticket_context(store.clone())));
            for chunk in message.chunks(3) {
                assert_eq!(session.read_handshake(chunk), Ok(false));
            }
            let ticket = store.take("example.com:443");
            assert_eq!(
                ticket.map(|ticket| ticket.max_early_data_size),
                storage.then_some(QUIC_MAX_EARLY_DATA_SIZE)
            );
            assert!(!session.connection.has_pending_message());
        }
    }

    /// Extension types of a ClientHello handshake message, in wire order.
    fn client_hello_extension_types(ch: &[u8]) -> Vec<u16> {
        assert_eq!(ch[0], 0x01, "expected a ClientHello handshake message");
        let mut pos = 4 + 2 + 32; // header + legacy_version + random
        pos += 1 + ch[pos] as usize; // legacy_session_id
        pos += 2 + u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize; // cipher_suites
        pos += 1 + ch[pos] as usize; // legacy_compression_methods
        let ext_total = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total;
        assert!(ext_end <= ch.len(), "ClientHello extension block truncated");

        let mut types = Vec::new();
        while pos + 4 <= ext_end {
            types.push(u16::from_be_bytes([ch[pos], ch[pos + 1]]));
            let ext_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
            pos += 4 + ext_len;
        }
        types
    }

    fn ticket_with_early_data_size(max_early_data_size: u32) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![1, 2, 3],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            used_extended_master_secret: None,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn: Some("h3".into()),
            alps: Default::default(),
            hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size,
            peer_transport_parameters: Some(vec![0x01, 0x00]),
        }
    }

    // Obtain the opaque session-issuance context through an independent,
    // authenticated handshake before injecting protocol-specific test values.
    fn authenticated_ticket_store(
        config: &mut LktlsQuicClientConfig,
        hostname: &str,
        ticket: SessionTicketData,
    ) -> Arc<lktls::session_store::InMemorySessionStore> {
        static IDENTITY: std::sync::OnceLock<(CertificateDer<'static>, Vec<u8>)> =
            std::sync::OnceLock::new();
        let (certificate, key) = IDENTITY.get_or_init(|| {
            let identity = generate_simple_self_signed(vec![
                "example.com".into(),
                "private.example.com".into(),
            ])
            .unwrap();
            (
                identity.cert.der().clone(),
                identity.signing_key.serialize_der(),
            )
        });
        config.template = config
            .template
            .clone()
            .custom_ca_anchors(Some(Arc::new(vec![trust_anchor_from_der(certificate)])));
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let mut warm = config
            .clone()
            .with_profile(presets::chrome_155_quic())
            .session_store(store.clone());
        warm.handshake.ech_config_list = None;
        warm.handshake.alps_payload = None;
        let mut client = warm.prepare_quic_handshake(hostname, Vec::new()).unwrap();
        let mut server = rustls::quic::ServerConnection::new(
            Arc::new(stream_reuse_server_config(certificate, key, false, false)),
            rustls::quic::Version::V1,
            Vec::new(),
        )
        .unwrap();
        let mut to_server = client.start().unwrap();
        for _ in 0..16 {
            if !to_server.is_empty() {
                server.read_hs(&to_server).unwrap();
                to_server.clear();
            }
            let mut to_client = Vec::new();
            let _ = server.write_hs(&mut to_client);
            client.feed(&to_client);
            loop {
                match client.progress().unwrap() {
                    QuicHandshakeOutput::SendData(data) => to_server.extend_from_slice(&data),
                    QuicHandshakeOutput::HandshakeSecretsReady { to_send, .. } => {
                        to_server.extend_from_slice(&to_send)
                    }
                    QuicHandshakeOutput::NeedData => break,
                    QuicHandshakeOutput::Done { to_send, result } => {
                        server.read_hs(&to_send).unwrap();
                        assert!(!server.is_handshaking());
                        let context = result.session_ticket_ctx.unwrap();
                        context.store.store(&context.host_key, ticket);
                        return store;
                    }
                }
            }
        }
        panic!("fixture authentication did not complete");
    }

    fn start_quic_session_with_ticket(ticket: SessionTicketData) -> (Box<dyn Session>, Vec<u16>) {
        // A QUIC preset: its extension order is the one that carries
        // `early_data`, so the ClientHello below actually reflects what the
        // ticket permits.
        let mut profile = presets::chrome_146_quic();
        profile.session_resumption.tls13_psk = true;
        start_quic_session_with_profile_and_ticket(profile, ticket)
    }

    fn start_quic_session_with_profile_and_ticket(
        profile: TlsProfile,
        ticket: SessionTicketData,
    ) -> (Box<dyn Session>, Vec<u16>) {
        start_quic_session_with_config_and_ticket(LktlsQuicClientConfig::new(profile), ticket)
    }

    fn start_quic_session_with_config_and_ticket(
        mut config: LktlsQuicClientConfig,
        ticket: SessionTicketData,
    ) -> (Box<dyn Session>, Vec<u16>) {
        let store = authenticated_ticket_store(&mut config, "example.com", ticket);
        let config = Arc::new(config.session_store(store));
        let transport_parameters = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
        let mut session =
            ProtoClientConfig::start_session(config, 1, "example.com", &transport_parameters)
                .expect("start_session");
        let mut client_hello = Vec::new();
        assert!(
            session.write_handshake(&mut client_hello).is_none(),
            "the initial ClientHello yields no keys yet"
        );
        let extensions = client_hello_extension_types(&client_hello);
        (session, extensions)
    }

    #[test]
    fn quic_early_crypto_requires_emitted_early_data() {
        let mut profile = presets::chrome_144();
        profile.alpn_protocols = vec!["h3".into()];
        let (session, extensions) = start_quic_session_with_profile_and_ticket(
            profile,
            ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE),
        );
        assert!(
            extensions.contains(&0x0029),
            "ordinary PSK resumption remains enabled"
        );
        assert!(
            !extensions.contains(&0x002a),
            "the TCP profile omits early_data"
        );
        assert!(
            session.early_crypto().is_none(),
            "missing early_data must prevent 0-RTT keys"
        );
    }

    #[test]
    fn quic_early_crypto_requires_enabled_psk() {
        let mut profile = presets::chrome_155_quic();
        profile.session_resumption.tls13_psk = false;
        let (session, extensions) = start_quic_session_with_profile_and_ticket(
            profile,
            ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE),
        );
        assert!(!extensions.contains(&0x0029), "PSK is disabled");
        assert!(
            !extensions.contains(&0x002a),
            "early_data requires a PSK offer"
        );
        assert!(
            session.early_crypto().is_none(),
            "disabled PSK must prevent 0-RTT keys"
        );
    }

    #[test]
    fn quic_early_crypto_requires_compatible_ticket_alpn() {
        let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
        ticket.alpn = Some("h2".into());
        let (session, extensions) =
            start_quic_session_with_profile_and_ticket(presets::chrome_155_quic(), ticket);
        assert!(
            !extensions.contains(&0x0029),
            "incompatible ticket must not resume"
        );
        assert!(
            !extensions.contains(&0x002a),
            "early_data requires a PSK offer"
        );
        assert!(
            session.early_crypto().is_none(),
            "incompatible ALPN must prevent 0-RTT keys"
        );
    }

    #[test]
    fn quic_early_crypto_available_for_compatible_quic_profile() {
        let (session, extensions) = start_quic_session_with_profile_and_ticket(
            presets::chrome_155_quic(),
            ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE),
        );
        assert!(extensions.contains(&0x0029));
        assert!(extensions.contains(&0x002a));
        assert!(
            session.early_crypto().is_some(),
            "valid QUIC 0-RTT remains available"
        );
    }

    #[test]
    fn quic_early_crypto_agrees_with_offer_for_cached_alps_settings() {
        let settings_a = lkh3::encode_alps_h3_settings(&lkh3::chrome_155_h3());
        let mut changed_profile = lkh3::chrome_155_h3();
        changed_profile.qpack_blocked_streams += 1;
        let settings_b = lkh3::encode_alps_h3_settings(&changed_profile);
        assert_ne!(settings_a, settings_b);

        for (name, current_settings, expected_early) in [
            ("same", Some(settings_a.clone()), true),
            ("changed", Some(settings_b.clone()), false),
            ("empty", Some(Vec::new()), false),
            ("disabled", None, false),
        ] {
            let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
            ticket.alps = AlpsSessionState::Negotiated {
                client_settings: settings_a.clone(),
                server_settings: settings_b.clone(),
            };
            let alps_offered = current_settings.is_some();
            let mut config = LktlsQuicClientConfig::new(presets::chrome_155_quic());
            if let Some(settings) = current_settings {
                config = config.alps_payload(settings);
            }
            let (session, extensions) = start_quic_session_with_config_and_ticket(config, ticket);
            let early_offered = extensions.contains(&0x002a);
            let early_crypto = session.early_crypto().is_some();
            assert!(
                extensions.contains(&0x0029),
                "{name}: ordinary PSK remains available"
            );
            assert_eq!(extensions.contains(&0x44cd), alps_offered, "{name}");
            assert_eq!(
                early_offered, expected_early,
                "{name}: serialized early_data"
            );
            assert_eq!(
                early_crypto, early_offered,
                "{name}: keys must match the offer"
            );
            eprintln!(
                "cached ALPS A/current {name}: early_data={early_offered}, early_crypto={early_crypto}"
            );
        }
    }

    fn quic_diagnostic_and_production_early_data(
        profile: TlsProfile,
        ticket: Option<SessionTicketData>,
        ech: bool,
        expected_early_data: bool,
        expected_psk: bool,
    ) -> (bool, bool) {
        let mut config = LktlsQuicClientConfig::new(profile).port(8443);
        let mut diagnostic_store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let mut production_store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        if let Some(ticket) = ticket {
            diagnostic_store =
                authenticated_ticket_store(&mut config, "private.example.com", ticket.clone());
            production_store =
                authenticated_ticket_store(&mut config, "private.example.com", ticket);
        }
        if ech {
            config = config.ech_config(local_rejection_ech_config("public.example.com"));
        }
        let parameters = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
        let mut encoded_parameters = Vec::new();
        parameters.write(&mut encoded_parameters);
        let diagnostic = config
            .clone()
            .session_store(diagnostic_store)
            .emit_initial_client_hello("private.example.com", encoded_parameters)
            .unwrap();
        let mut session = Arc::new(config.session_store(production_store))
            .start_session(1, "private.example.com", &parameters)
            .unwrap();
        let mut production = Vec::new();
        assert!(session.write_handshake(&mut production).is_none());
        assert_eq!(session.early_crypto().is_some(), expected_early_data);

        let diagnostic = lkprofile::parse_client_hello(&diagnostic).unwrap();
        let production = lkprofile::parse_client_hello(&production).unwrap();
        assert_eq!(diagnostic.cipher_suites, production.cipher_suites);
        assert_eq!(diagnostic.session_id_length, production.session_id_length);
        for (path, hello) in [("production", &production), ("diagnostic", &diagnostic)] {
            let extension = |kind| {
                hello
                    .extensions
                    .iter()
                    .find(|extension| extension.extension_type == kind)
            };
            assert_eq!(
                extension(0x0029).is_some(),
                expected_psk && !ech,
                "{path}, ECH={ech}: real ECH keeps the PSK in ClientHelloInner"
            );
            let server_name = if ech {
                "public.example.com"
            } else {
                "private.example.com"
            };
            assert_eq!(
                &extension(0x0000).unwrap().data[5..],
                server_name.as_bytes()
            );
            if ech {
                assert_eq!(extension(0xfe0d).unwrap().data[0], 0, "ECH outer form");
            }
        }
        for kind in [0x0010, 0x0039] {
            let payload = |hello: &lkprofile::ParsedClientHello| {
                hello
                    .extensions
                    .iter()
                    .find(|extension| extension.extension_type == kind)
                    .unwrap()
                    .data
                    .clone()
            };
            assert_eq!(payload(&diagnostic), payload(&production));
        }
        let types = |hello: &lkprofile::ParsedClientHello| {
            let mut types = hello
                .extensions
                .iter()
                .map(|extension| extension.extension_type)
                .collect::<Vec<_>>();
            types.sort_unstable();
            types
        };
        assert_eq!(types(&diagnostic), types(&production));
        let early_data = |hello: &lkprofile::ParsedClientHello| {
            hello
                .extensions
                .iter()
                .any(|extension| extension.extension_type == 0x002a)
        };
        (early_data(&diagnostic), early_data(&production))
    }

    #[test]
    fn quic_diagnostic_sanitizes_non_quic_ticket_allowance() {
        let early_data = quic_diagnostic_and_production_early_data(
            presets::chrome_155_quic(),
            Some(ticket_with_early_data_size(16_384)),
            false,
            false,
            true,
        );
        assert_eq!(early_data, (false, false));
    }

    #[test]
    fn quic_diagnostic_sanitizes_non_quic_ticket_allowance_with_ech() {
        let early_data = quic_diagnostic_and_production_early_data(
            presets::chrome_155_quic(),
            Some(ticket_with_early_data_size(16_384)),
            true,
            false,
            true,
        );
        assert_eq!(early_data, (false, false));
    }

    #[test]
    fn quic_diagnostic_sanitizes_missing_transport_parameters() {
        let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
        ticket.peer_transport_parameters = None;
        let early_data = quic_diagnostic_and_production_early_data(
            presets::chrome_155_quic(),
            Some(ticket),
            false,
            false,
            true,
        );
        assert_eq!(early_data, (false, false));
    }

    #[test]
    fn quic_diagnostic_sanitizes_missing_transport_parameters_with_ech() {
        let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
        ticket.peer_transport_parameters = None;
        let early_data = quic_diagnostic_and_production_early_data(
            presets::chrome_155_quic(),
            Some(ticket),
            true,
            false,
            true,
        );
        assert_eq!(early_data, (false, false));
    }

    #[test]
    fn quic_diagnostic_preserves_ticket_selection_and_ech_outer() {
        for ech in [false, true] {
            for case in 0..6 {
                let mut profile = presets::chrome_155_quic();
                let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
                match case {
                    2 => ticket.max_early_data_size = 0,
                    3 => ticket.alpn = Some("h2".into()),
                    4 => profile.session_resumption.tls13_psk = false,
                    5 => ticket.tls_version = TicketTlsVersion::Tls12,
                    _ => {}
                }
                let early_data = quic_diagnostic_and_production_early_data(
                    profile,
                    (case != 0).then_some(ticket),
                    ech,
                    case == 1,
                    matches!(case, 1 | 2),
                );
                assert_eq!(early_data, (case == 1, case == 1), "case={case}, ECH={ech}");
            }
        }
    }

    /// A stored ticket whose `max_early_data_size` is not the 0xffffffff QUIC
    /// mandates is not a QUIC 0-RTT ticket. Resumption still happens, but no
    /// early keys are derived — and, just as important, the ClientHello must
    /// not advertise `early_data` (0x002a) we have no keys to back.
    #[test]
    fn non_quic_early_data_size_disables_zero_rtt_and_the_early_data_extension() {
        const EARLY_DATA: u16 = 0x002a;
        const PRE_SHARED_KEY: u16 = 0x0029;

        let (session, extensions) =
            start_quic_session_with_ticket(ticket_with_early_data_size(16_384));
        assert!(
            session.early_crypto().is_none(),
            "a ticket with max_early_data_size = 16384 must not enable 0-RTT over QUIC",
        );
        assert!(
            !extensions.contains(&EARLY_DATA),
            "the ClientHello must not offer early_data without early keys; got {extensions:?}",
        );
        assert!(
            extensions.contains(&PRE_SHARED_KEY),
            "resumption itself is still valid — only 0-RTT is refused; got {extensions:?}",
        );

        let (session, extensions) =
            start_quic_session_with_ticket(ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE));
        assert!(
            session.early_crypto().is_some(),
            "0xffffffff is the value QUIC mandates and must enable 0-RTT",
        );
        assert!(
            extensions.contains(&EARLY_DATA),
            "a legal QUIC 0-RTT ticket must offer early_data; got {extensions:?}",
        );
    }

    #[test]
    fn quic_early_data_requires_transport_parameters_in_the_ticket() {
        const EARLY_DATA: u16 = 0x002a;
        const PRE_SHARED_KEY: u16 = 0x0029;

        let mut ticket = ticket_with_early_data_size(QUIC_MAX_EARLY_DATA_SIZE);
        ticket.peer_transport_parameters = None;
        let (session, extensions) = start_quic_session_with_ticket(ticket);

        assert!(
            session.early_crypto().is_none(),
            "QUIC 0-RTT must not be enabled without cached transport parameters",
        );
        assert!(
            !extensions.contains(&EARLY_DATA),
            "early_data must not be offered without cached transport parameters; got {extensions:?}",
        );
        assert!(
            extensions.contains(&PRE_SHARED_KEY),
            "ordinary PSK resumption should remain available; got {extensions:?}",
        );
    }
    #[test]
    fn hrr_rejects_zero_rtt_before_handshake_completion() {
        let mut config = LktlsQuicClientConfig::new(presets::chrome_155_quic());
        let store = authenticated_ticket_store(
            &mut config,
            "example.com",
            SessionTicketData {
                ticket: vec![1, 2, 3],
                resumption_psk: vec![0xAA; 32],
                tls_version: TicketTlsVersion::Tls13,
                used_extended_master_secret: None,
                cipher_suite: 0x1301,
                lifetime_secs: 3600,
                age_add: 0,
                received_at: std::time::Instant::now(),
                alpn: Some("h3".into()),
                alps: Default::default(),
                hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
                aead_algorithm: AeadAlgorithm::Aes128Gcm,
                master_secret: Vec::new(),
                // RFC 9001 §4.6.1: the only value QUIC permits, and therefore
                // the only one that makes 0-RTT available here.
                max_early_data_size: QUIC_MAX_EARLY_DATA_SIZE,
                peer_transport_parameters: Some(vec![0x01, 0x00]),
            },
        );

        let config = Arc::new(config.session_store(store));
        let transport_parameters = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
        let mut session =
            ProtoClientConfig::start_session(config, 1, "example.com", &transport_parameters)
                .unwrap();

        assert!(session.early_crypto().is_some());
        assert!(!session.early_data_rejected());
        let mut ch1 = Vec::new();
        assert!(session.write_handshake(&mut ch1).is_none());
        let offered = lkprofile::parse_client_hello(&ch1).unwrap();
        let key_shares = offered
            .extensions
            .iter()
            .find(|extension| extension.extension_type == 0x0033)
            .unwrap();
        assert!(
            !lkprofile::extract_key_share_curves(&key_shares.data).contains(&0x0018),
            "HRR must select a group absent from CH1 key_share"
        );
        assert!(client_hello_extension_types(&ch1).contains(&0x002a));
        let sid_len = ch1[38] as usize;
        let session_id = &ch1[39..39 + sid_len];
        let hrr = build_hrr(session_id, 0x1301, 0x0018);

        assert!(!session.read_handshake(&hrr).unwrap());
        assert!(session.early_data_rejected());
        let mut ch2 = Vec::new();
        assert!(session.write_handshake(&mut ch2).is_none());
        assert!(!ch2.is_empty());
        let offered = lkprofile::parse_client_hello(&ch2).unwrap();
        let key_shares = offered
            .extensions
            .iter()
            .find(|extension| extension.extension_type == 0x0033)
            .unwrap();
        assert_eq!(
            lkprofile::extract_key_share_curves(&key_shares.data),
            [0x0018]
        );
        assert!(!client_hello_extension_types(&ch2).contains(&0x002a));
    }

    #[test]
    fn local_tls_alert_maps_to_quic_crypto_error() {
        let error = TlsError::local_alert(
            lktls::error::AlertDescription::IllegalParameter,
            "invalid HRR",
        );
        let transport = map_tls_error(error);
        assert_eq!(
            transport.code,
            TransportErrorCode::crypto(lktls::error::AlertDescription::IllegalParameter.as_byte())
        );
    }
}
