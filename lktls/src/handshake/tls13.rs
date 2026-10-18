//! TLS 1.3 handshake state machine.
//!
//! Drives the full TLS 1.3 handshake flow:
//!
//! ```text
//! Client                                Server
//! ------                                ------
//! ClientHello          -------->
//!                                       ServerHello
//!                                       EncryptedExtensions
//!                                       Certificate*
//!                                       CertificateVerify*
//!                      <--------        Finished
//! Finished             -------->
//! [Application Data]   <------->        [Application Data]
//! ```
//!
//! Also supports HelloRetryRequest (HRR):
//!
//! ```text
//! ClientHello          -------->
//!                      <--------        HelloRetryRequest
//! ClientHello2         -------->
//!                                       ServerHello
//!                                       ... (continues as above)
//! ```

use aws_lc_rs::digest;
use aws_lc_rs::hmac;

use std::sync::Arc;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::{hkdf_expand_label, hkdf_extract, HkdfAlgorithm, HkdfPrk};
use crate::crypto::kx::{self, EphemeralKeyPair, KxGroup};
use crate::error::{AlertDescription, Result, TlsError};
use crate::extensions::pre_shared_key::{self, PskIdentity};
use crate::extensions::quic_transport_params::{decode_transport_params, QuicTransportParams};
use crate::extensions::record_size_limit::parse_peer_record_size_limit;
use crate::handshake::client_hello::{
    extract_ech_extension, profile_offers_alps_protocol, ClientHelloBuilder, EchRetryState,
};
use crate::handshake::handshake_type;
use crate::handshake::server_hello::{self, ServerHello};
use crate::profile::types::{ext_type, ExtensionSource, ExtensionSpec, TlsProfile, TlsVersion};
use crate::session_store::{AlpsSessionState, SessionTicketData};
use crate::verify::policy::VerificationPolicy;

use crate::crypto::to_hex;

// ---------------------------------------------------------------------------
// Transcript Hash
// ---------------------------------------------------------------------------

/// Running transcript hash for the TLS 1.3 handshake.
///
/// Accumulates all handshake messages and provides the current hash value
/// at any point (used for key derivation at multiple stages).
#[derive(Clone)]
struct TranscriptHash {
    context: digest::Context,
    algorithm: HkdfAlgorithm,
}

impl TranscriptHash {
    fn new(algorithm: HkdfAlgorithm) -> Self {
        Self {
            context: digest::Context::new(Self::ring_algorithm(algorithm)),
            algorithm,
        }
    }

    /// Feed handshake message bytes into the transcript.
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Get the current hash value without consuming the context.
    fn current_hash(&self) -> Vec<u8> {
        self.context.clone().finish().as_ref().to_vec()
    }

    /// Replace the transcript with a synthetic `message_hash` message for HRR.
    ///
    /// Per RFC 8446 Section 4.4.1: when HelloRetryRequest is received, the
    /// transcript is replaced with:
    ///   Hash(message_hash || HRR || ...)
    /// where message_hash = [0xFE, 0, 0, Hash.length, Hash(CH1)]
    fn replace_with_message_hash(&mut self) {
        let hash = self.current_hash();
        let hash_len = hash.len();

        // Build the synthetic message_hash handshake message
        let mut msg = Vec::with_capacity(4 + hash_len);
        msg.push(handshake_type::MESSAGE_HASH);
        msg.push(0);
        msg.push(0);
        msg.push(hash_len as u8);
        msg.extend_from_slice(&hash);

        // Reset the context and feed the synthetic message
        self.context = digest::Context::new(Self::ring_algorithm(self.algorithm));
        self.context.update(&msg);
    }

    fn ring_algorithm(algo: HkdfAlgorithm) -> &'static digest::Algorithm {
        match algo {
            HkdfAlgorithm::Sha256 => &digest::SHA256,
            HkdfAlgorithm::Sha384 => &digest::SHA384,
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Represents the current state of a TLS 1.3 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13State {
    /// Initial state — ready to build ClientHello.
    Start,
    /// ClientHello sent, waiting for ServerHello.
    WaitServerHello,
    /// ServerHello received, waiting for EncryptedExtensions.
    WaitEncryptedExtensions,
    /// Waiting for server Certificate (may be skipped with PSK).
    WaitCertificate,
    /// Waiting for CertificateVerify.
    WaitCertificateVerify,
    /// Waiting for server Finished.
    WaitFinished,
    /// Handshake complete, ready for application data.
    Connected,
}

/// Action the caller should take after processing a handshake message.
#[derive(Debug)]
pub enum HandshakeAction {
    /// Install handshake traffic keys for encrypting/decrypting.
    /// After this, subsequent records from the server are encrypted.
    InstallHandshakeKeys(HandshakeKeys),

    /// Continue reading — more messages expected.
    ContinueReading,

    /// The handshake is complete. The caller should:
    /// 1. Send any TCP `client_end_of_early_data` with its early write key.
    /// 2. Send optional client handshake messages and `client_finished` with
    ///    the handshake write key.
    /// 3. Install the application traffic keys.
    Complete(Box<HandshakeComplete>),

    /// HelloRetryRequest received. Send this new ClientHello (plaintext).
    RetryClientHello(Vec<u8>),
}

/// Handshake traffic keys (installed after ServerHello).
#[derive(Debug)]
pub struct HandshakeKeys {
    /// HKDF algorithm for this cipher suite.
    pub hkdf_algorithm: HkdfAlgorithm,
    /// AEAD algorithm for this cipher suite.
    pub aead_algorithm: AeadAlgorithm,
    /// Server handshake traffic secret.
    pub server_secret: Vec<u8>,
    /// Client handshake traffic secret.
    pub client_secret: Vec<u8>,
    /// Server handshake write key (for decrypting server messages).
    pub server_key: Vec<u8>,
    /// Server handshake write IV.
    pub server_iv: Vec<u8>,
    /// Client handshake write key (for encrypting client Finished).
    pub client_key: Vec<u8>,
    /// Client handshake write IV.
    pub client_iv: Vec<u8>,
}

/// TCP EndOfEarlyData message and its early-epoch write keys.
#[derive(Debug)]
pub struct EndOfEarlyDataFlight {
    /// Empty EndOfEarlyData handshake message, included before client Finished.
    pub message: Vec<u8>,
    /// AEAD selected by the resumed ticket.
    pub aead_algorithm: AeadAlgorithm,
    /// Client early-data write key.
    pub client_key: Vec<u8>,
    /// Client early-data write IV.
    pub client_iv: Vec<u8>,
}

/// Data returned when the handshake completes.
#[derive(Debug)]
pub struct HandshakeComplete {
    /// TCP-only early-data end marker, sent before the handshake-key flight.
    /// The driver sends no early application data, so this uses early sequence 0.
    /// Always `None` for QUIC, HRR, or rejected early data.
    pub client_end_of_early_data: Option<EndOfEarlyDataFlight>,
    /// Optional Client EncryptedExtensions message (ALPS).
    /// Must be sent *before* `client_finished`, encrypted with handshake keys.
    /// `None` if ALPS was not negotiated.
    pub client_encrypted_extensions: Option<Vec<u8>>,
    /// Empty client Certificate message sent when the server requested client
    /// authentication but no client certificate is configured.
    pub client_certificate: Option<Vec<u8>>,
    /// Client Finished handshake message bytes (to be sent encrypted
    /// with the handshake write key, NOT the application key).
    pub client_finished: Vec<u8>,
    /// Application traffic keys for post-handshake communication.
    pub traffic_secrets: TrafficSecrets,
    /// The ALPN protocol negotiated by the server (from EncryptedExtensions).
    /// `None` if the server didn't include ALPN in EncryptedExtensions.
    pub negotiated_alpn: Option<String>,
    /// Effective ALPS state, including settings inherited on accepted 0-RTT.
    pub alps: AlpsSessionState,
    /// The server's RFC 8449 `record_size_limit` from EncryptedExtensions.
    ///
    /// `None` if the server did not send the extension, in which case records
    /// are chunked at the protocol maximum exactly as before.
    pub peer_record_size_limit: Option<u16>,
    /// The resumption master secret (for deriving PSK from NewSessionTickets).
    /// This is needed by the connector to compute `resumption_psk` for tickets
    /// received as post-handshake messages.
    pub resumption_master_secret: Vec<u8>,
    /// The cipher suite negotiated by the server.
    /// Used when storing session tickets for PSK resumption.
    pub negotiated_cipher_suite: u16,
    /// The server's certificate chain (DER, leaf first), as received in the
    /// Certificate message. Empty on a resumed (PSK) handshake that sends none.
    pub server_certificates: Vec<Vec<u8>>,

    /// ECH retry configs received from the server in EncryptedExtensions.
    ///
    /// If the server supports ECH and the client's ECH attempt failed (or was
    /// GREASE), the server may provide updated ECHConfigList data here.  The
    /// caller should store this for subsequent connections to enable real ECH.
    ///
    /// `None` if the server did not include `encrypted_client_hello` in EE.
    pub ech_retry_configs: Option<Vec<u8>>,

    /// Whether the server accepted real ECH.
    ///
    /// `true` if the client offered real ECH and the server's accept
    /// confirmation matched.  `false` if ECH was not offered, was rejected,
    /// or only GREASE was sent.
    pub ech_accepted: bool,
    /// Whether *real* ECH was offered in the ClientHello.
    ///
    /// Distinguishes "ECH was never offered" from "ECH was offered and the
    /// server rejected it" — only the latter must abort with `ech_required`.
    /// GREASE ECH does not set this: it is not an ECH offer, and a server that
    /// ignores it has rejected nothing.
    pub ech_offered: bool,

    /// Server QUIC transport parameters from EncryptedExtensions.
    pub peer_quic_transport_params: Option<QuicTransportParams>,
    /// Whether the server accepted early data (0-RTT).
    pub early_data_accepted: bool,
    /// Whether the verified handshake selected an offered resumption PSK.
    pub session_resumed: bool,
}

/// Traffic encryption keys derived at the end of the handshake.
#[derive(Debug)]
pub struct TrafficSecrets {
    /// AEAD algorithm.
    pub aead_algorithm: AeadAlgorithm,
    /// HKDF algorithm (for KeyUpdate derivation).
    pub hkdf_algorithm: crate::crypto::hkdf::HkdfAlgorithm,
    /// Client application traffic key.
    pub client_key: Vec<u8>,
    /// Client application traffic IV.
    pub client_iv: Vec<u8>,
    /// Server application traffic key.
    pub server_key: Vec<u8>,
    /// Server application traffic IV.
    pub server_iv: Vec<u8>,
    /// Server application traffic secret (needed for KeyUpdate derivation).
    pub server_app_secret: Vec<u8>,
    /// Client application traffic secret (needed for KeyUpdate write-side rotation).
    pub client_app_secret: Vec<u8>,
    /// Exporter master secret (RFC 8446 §7.5), backing `export_keying_material`.
    pub exporter_master_secret: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Cipher suite info
// ---------------------------------------------------------------------------

/// Map a TLS 1.3 cipher suite to its component algorithms.
fn cipher_suite_info(suite: u16) -> Result<(HkdfAlgorithm, AeadAlgorithm)> {
    match suite {
        0x1301 => Ok((HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm)),
        0x1302 => Ok((HkdfAlgorithm::Sha384, AeadAlgorithm::Aes256Gcm)),
        0x1303 => Ok((HkdfAlgorithm::Sha256, AeadAlgorithm::Chacha20Poly1305)),
        _ => Err(TlsError::local_alert(
            AlertDescription::IllegalParameter,
            format!("unsupported cipher suite: 0x{suite:04x}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// ClientHello re-parsing
// ---------------------------------------------------------------------------

/// Walk the extension block of a ClientHello handshake message we produced,
/// yielding `(extension_type, extension_body)` in wire order.
///
/// Both handshake versions need to answer "what did we actually offer?" after
/// the fact — TLS 1.3 to enforce RFC 8446 §4.2 (no unsolicited server
/// extensions), TLS 1.2 to enforce RFC 8422 §5.4 / RFC 5246 §7.4.1.4.1 (the
/// server must select a curve and a signature algorithm from ours). Reading it
/// back off the bytes we sent, rather than off the profile, keeps the answer
/// exact when the builder adds, drops, or permutes extensions at runtime.
///
/// Returns `None` if `message` is not a well-formed ClientHello, which callers
/// treat as "the offer is unknown" rather than as a protocol violation — the
/// message came from us, so a parse failure is a local bug, not a peer attack.
pub(crate) fn client_hello_extensions(message: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    if message.first() != Some(&handshake_type::CLIENT_HELLO) {
        return None;
    }
    // Handshake header (4) + legacy_version (2) + random (32)
    let body = message.get(4..)?;
    let session_id_len = *body.get(34)? as usize;
    let mut pos = 35 + session_id_len;
    let cipher_suites_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(cipher_suites_len)?;
    let compression_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(compression_len)?;
    if pos == body.len() {
        return Some(Vec::new()); // TLS 1.2 may omit the extension block.
    }
    let extensions_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    let mut extensions = Vec::new();
    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let extension_end = pos.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        extensions.push((extension_type, &body[pos..extension_end]));
        pos = extension_end;
    }
    if pos != extensions_end {
        return None;
    }
    Some(extensions)
}

/// The extension types present in a ClientHello we produced, in wire order.
pub(crate) fn client_hello_offered_extensions(message: &[u8]) -> Option<Vec<u16>> {
    Some(
        client_hello_extensions(message)?
            .into_iter()
            .map(|(extension_type, _)| extension_type)
            .collect(),
    )
}

pub(crate) fn client_hello_legacy_offer(message: &[u8]) -> Option<(Vec<u16>, Vec<u8>)> {
    if message.first() != Some(&handshake_type::CLIENT_HELLO) {
        return None;
    }
    let body = message.get(4..)?;
    let session_id_len = *body.get(34)? as usize;
    let mut offset = 35 + session_id_len;
    let length = u16::from_be_bytes([*body.get(offset)?, *body.get(offset + 1)?]) as usize;
    offset += 2;
    if length < 2 || !length.is_multiple_of(2) {
        return None;
    }
    let suites = body
        .get(offset..offset + length)?
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_be_bytes)
        .collect();
    offset += length;
    let compression_len = *body.get(offset)? as usize;
    offset += 1;
    if compression_len == 0 {
        return None;
    }
    let compression = body.get(offset..offset + compression_len)?.to_vec();
    Some((suites, compression))
}

// ---------------------------------------------------------------------------
// Tls13Handshake
// ---------------------------------------------------------------------------

/// Manages the TLS 1.3 handshake process.
pub struct Tls13Handshake {
    /// Current state.
    state: Tls13State,
    /// The profile driving this handshake.
    profile: TlsProfile,
    /// Target server hostname (for SNI and cert verification).
    hostname: String,

    // --- Transcript ---
    /// Transcript hash context (initialized after we know the cipher suite).
    transcript: Option<TranscriptHash>,
    /// Buffered ClientHello bytes (before cipher suite is known).
    buffered_client_hello: Option<Vec<u8>>,

    // --- Key exchange ---
    /// Ephemeral key pairs generated for key_share.
    key_pairs: Vec<EphemeralKeyPair>,

    // --- Saved for HRR ---
    /// Client random from the first ClientHello.
    client_random: Option<[u8; 32]>,
    /// Session ID from the first ClientHello.
    session_id: Option<Vec<u8>>,
    /// Whether we have already processed an HRR.
    hrr_received: bool,
    /// GREASE values from the first ClientHello, reused in CH2 after HRR.
    grease_values: Option<crate::extensions::grease::GreaseValues>,
    /// Exact extension permutation selected for CH1.
    extension_order: Option<Vec<ExtensionSpec>>,
    /// Extension types actually emitted in the ClientHello we sent.
    ///
    /// Read back off the finished ClientHello bytes rather than off the profile
    /// so it is the wire truth: it already accounts for the extensions the
    /// builder adds or drops at runtime (`pre_shared_key`, `early_data`,
    /// `quic_transport_parameters`, ALPS suppression, GREASE placement) and for
    /// any permutation applied. Backs the RFC 8446 §4.2 rule that the server
    /// MUST NOT answer with an extension we never offered.
    ///
    /// `None` means the ClientHello has not been built through this handshake
    /// (or was not parseable), in which case there is nothing to compare
    /// against and the unsolicited-extension check is skipped.
    offered_extensions: Option<Vec<u16>>,
    /// Actual ALPN identifiers from the active emitted ClientHello, including
    /// RawBytes overrides; absent until a ClientHello has been recorded.
    offered_alpn_protocols: Option<Vec<Vec<u8>>>,
    /// Active serialized supported_versions payload, retained after HRR consumes
    /// the ClientHello transcript buffer. None when the extension is absent.
    offered_supported_versions: Option<Vec<u8>>,
    /// Complete fake ECH extension from CH1, reused byte-for-byte in CH2.
    ech_grease_extension: Option<Vec<u8>>,

    // --- Negotiated parameters ---
    /// Selected cipher suite.
    cipher_suite: Option<u16>,
    /// HKDF algorithm (from cipher suite).
    hkdf_algorithm: Option<HkdfAlgorithm>,
    /// AEAD algorithm (from cipher suite).
    aead_algorithm: Option<AeadAlgorithm>,

    // --- Key schedule ---
    /// Handshake secret (for deriving traffic secrets + master secret).
    handshake_secret: Option<HkdfPrk>,
    /// Client handshake traffic secret.
    client_hs_traffic_secret: Option<Vec<u8>>,
    /// Server handshake traffic secret.
    server_hs_traffic_secret: Option<Vec<u8>>,

    // --- Server certificates ---
    /// Server certificate chain (DER-encoded, leaf first).
    server_certificates: Vec<Vec<u8>>,
    /// CertificateRequest context to echo in an empty client Certificate.
    client_certificate_request_context: Option<Vec<u8>>,

    // --- ALPS ---
    /// Optional ALPS payload (pre-encoded H2 SETTINGS bytes from upper layer).
    alps_payload: Option<Vec<u8>>,
    /// Server ALPS data received in EncryptedExtensions (opaque blob).
    server_alps_data: Option<Vec<u8>>,
    /// The ALPS extension code point negotiated by the server (0x4469 or 0x44CD).
    alps_code_point: Option<u16>,

    // --- Negotiated ALPN ---
    /// The ALPN protocol selected by the server (extracted from EncryptedExtensions).
    negotiated_alpn: Option<String>,

    /// The server's RFC 8449 `record_size_limit`, from EncryptedExtensions.
    ///
    /// RFC 8449 §4: "In TLS 1.3, the server sends the 'record_size_limit'
    /// extension in the EncryptedExtensions message." It bounds the records we
    /// send to the server, not the ones it sends us.
    peer_record_size_limit: Option<u16>,

    // --- ECH ---
    /// Runtime ECHConfigList provided by the caller (raw DER bytes).
    /// When set, overrides the profile's `ech` mode for this handshake.
    ech_config_list: Option<Vec<u8>>,

    /// ECH retry configs received from the server in EncryptedExtensions.
    /// If present, the server supports ECH and provides updated configs
    /// that the client should use for subsequent connections.
    ech_retry_configs: Option<Vec<u8>>,

    /// QUIC transport parameters extension payload for ClientHello.
    quic_transport_parameters: Option<Vec<u8>>,

    /// Server QUIC transport parameters from EncryptedExtensions.
    peer_quic_transport_params: Option<QuicTransportParams>,

    /// Whether this handshake is operating in QUIC-TLS mode.
    quic_mode: bool,

    /// Whether the server accepted early data in EncryptedExtensions.
    early_data_accepted: bool,
    /// Prepared TCP end marker and keys from the actual initial PSK offer.
    client_end_of_early_data: Option<EndOfEarlyDataFlight>,

    /// Whether real ECH was offered in the ClientHello.
    ech_offered: bool,

    /// Whether the server accepted our real ECH offer.
    ech_accepted: bool,

    /// The raw inner ClientHello bytes (with Handshake header) for
    /// transcript switching when ECH is accepted.
    ech_inner_hello: Option<Vec<u8>>,

    /// Real-ECH HPKE state retained for CH2 after HRR.
    ech_retry_state: Option<EchRetryState>,

    /// ECH acceptance signalled by HRR, when an HRR was received.
    ech_hrr_accepted: Option<bool>,

    /// Raw HRR message bytes, preserved for ECH+HRR transcript reconstruction.
    hrr_raw_bytes: Option<Vec<u8>>,

    /// Raw CH2 (second ClientHello) bytes built from the inner hello,
    /// preserved for ECH+HRR transcript reconstruction.
    hrr_inner_ch2: Option<Vec<u8>>,

    // --- Certificate verification policy ---
    /// Certificate and signature verification policy.
    verification_policy: VerificationPolicy,
    /// Custom CA trust anchors (merged with Mozilla root store).
    custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,

    // --- PSK / Session Resumption ---
    /// Session ticket data for PSK resumption (set before `build_client_hello`).
    psk_ticket: Option<SessionTicketData>,
    /// TLS 1.2 session ticket data for the session_ticket extension.
    /// Set when the session store has a TLS 1.2 ticket; the data goes
    /// into the session_ticket extension (0x0023) instead of pre_shared_key.
    tls12_session_ticket_data: Option<Vec<u8>>,
    /// Whether the server accepted our PSK offer.
    psk_accepted: bool,
    /// The Early Secret derived from the PSK (cached to avoid recomputation).
    early_secret_from_psk: Option<HkdfPrk>,

    /// Optional key log callback (SSLKEYLOGFILE). When set, secrets are
    /// emitted at derivation time with zero extra storage.
    keylog_callback: Option<crate::KeyLogCallback>,
}

impl Tls13Handshake {
    /// Create a new TLS 1.3 handshake with the given profile and hostname.
    pub fn new(profile: TlsProfile, hostname: impl Into<String>) -> Self {
        Self {
            state: Tls13State::Start,
            profile,
            hostname: hostname.into(),
            transcript: None,
            buffered_client_hello: None,
            key_pairs: Vec::new(),
            client_random: None,
            session_id: None,
            hrr_received: false,
            grease_values: None,
            extension_order: None,
            offered_extensions: None,
            offered_alpn_protocols: None,
            offered_supported_versions: None,
            ech_grease_extension: None,
            cipher_suite: None,
            hkdf_algorithm: None,
            aead_algorithm: None,
            handshake_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
            server_certificates: Vec::new(),
            client_certificate_request_context: None,
            alps_payload: None,
            server_alps_data: None,
            alps_code_point: None,
            negotiated_alpn: None,
            peer_record_size_limit: None,
            ech_config_list: None,
            ech_retry_configs: None,
            quic_transport_parameters: None,
            peer_quic_transport_params: None,
            quic_mode: false,
            early_data_accepted: false,
            client_end_of_early_data: None,
            ech_offered: false,
            ech_accepted: false,
            ech_inner_hello: None,
            ech_retry_state: None,
            ech_hrr_accepted: None,
            hrr_raw_bytes: None,
            hrr_inner_ch2: None,
            verification_policy: VerificationPolicy::default(),
            custom_ca_anchors: None,
            psk_ticket: None,
            tls12_session_ticket_data: None,
            psk_accepted: false,
            early_secret_from_psk: None,
            keylog_callback: None,
        }
    }

    /// Returns the current handshake state.
    pub fn state(&self) -> Tls13State {
        self.state
    }

    /// Returns whether this handshake has processed a HelloRetryRequest.
    pub(crate) fn has_received_hrr(&self) -> bool {
        self.hrr_received
    }

    pub(crate) fn early_data_offer(&self) -> Option<(&SessionTicketData, &[u8])> {
        if self.state != Tls13State::WaitServerHello || self.hrr_received {
            return None;
        }
        let ticket = self.psk_ticket.as_ref()?;
        if ticket.max_early_data_size == 0 {
            return None;
        }
        let hello = if self.ech_offered {
            self.ech_inner_hello.as_deref()?
        } else {
            self.buffered_client_hello.as_deref()?
        };
        let extensions = client_hello_extensions(hello)?;
        let (_, early_data) = extensions
            .iter()
            .find(|(kind, _)| *kind == ext_type::EARLY_DATA)?;
        if !early_data.is_empty() {
            return None;
        }
        let (_, psk) = extensions
            .iter()
            .find(|(kind, _)| *kind == ext_type::PRE_SHARED_KEY)?;
        let identities_len = u16::from_be_bytes(psk.get(..2)?.try_into().ok()?) as usize;
        let identities = psk.get(2..2 + identities_len)?;
        let identity_len = u16::from_be_bytes(identities.get(..2)?.try_into().ok()?) as usize;
        if identity_len == 0
            || identities.get(2..2 + identity_len)? != ticket.ticket
            || identities.len() < 2 + identity_len + 4
        {
            return None;
        }
        Some((ticket, hello))
    }

    fn alps_allows_early_data(&self, ticket: &SessionTicketData) -> bool {
        match &ticket.alps {
            // Unknown preserves legacy compatibility without inventing prior
            // settings. Explicit absence also does not restrict early data.
            AlpsSessionState::Unknown | AlpsSessionState::NotNegotiated => true,
            AlpsSessionState::Negotiated {
                client_settings, ..
            } => {
                self.alps_payload.as_deref() == Some(client_settings.as_slice())
                    && ticket.alpn.as_deref().is_some_and(|protocol| {
                        profile_offers_alps_protocol(&self.profile, protocol.as_bytes())
                    })
            }
        }
    }

    fn effective_alps_state(&self) -> AlpsSessionState {
        if self.early_data_accepted {
            return self
                .psk_ticket
                .as_ref()
                .map_or(AlpsSessionState::Unknown, |ticket| ticket.alps.clone());
        }
        match (&self.server_alps_data, &self.alps_payload) {
            (Some(server_settings), Some(client_settings)) => AlpsSessionState::Negotiated {
                client_settings: client_settings.clone(),
                server_settings: server_settings.clone(),
            },
            (None, _) => AlpsSessionState::NotNegotiated,
            // A raw profile can advertise ALPS without configuring its client
            // settings. Do not record fabricated settings for such a profile.
            (Some(_), None) => AlpsSessionState::Unknown,
        }
    }

    /// Set optional ALPS payload (pre-encoded H2 SETTINGS bytes).
    ///
    /// This must be called before `build_client_hello()`.
    pub fn set_alps_payload(&mut self, payload: Vec<u8>) {
        self.alps_payload = Some(payload);
    }

    /// Set the certificate verification policy.
    pub fn set_verification_policy(&mut self, policy: VerificationPolicy) {
        self.verification_policy = policy;
    }

    /// Set custom CA trust anchors (merged with Mozilla root store).
    pub fn set_custom_ca_anchors(
        &mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) {
        self.custom_ca_anchors = Some(anchors);
    }

    /// Set an ECHConfigList for real ECH (raw DER bytes).
    ///
    /// Must be called before `build_client_hello()`.  When set, the
    /// ClientHello builder constructs an encrypted inner ClientHello
    /// (with real SNI) and embeds it in the outer ClientHello's ECH
    /// extension via HPKE encryption.
    ///
    /// The config can come from:
    /// - DNS HTTPS resource records (`ech` SvcParam)
    /// - A previous connection's `ech_retry_configs`
    /// - Manual configuration by the user
    pub fn set_ech_config(&mut self, config_list: Vec<u8>) {
        self.ech_config_list = Some(config_list);
    }

    /// Enable QUIC-TLS mode.
    pub fn enable_quic_mode(&mut self) {
        self.quic_mode = true;
    }

    /// Set the encoded QUIC transport parameters extension payload.
    pub fn set_quic_transport_parameters(&mut self, payload: Vec<u8>) {
        self.quic_transport_parameters = Some(payload);
    }

    /// Set a session ticket for PSK resumption.
    ///
    /// Must be called before `build_client_hello()`. If set, the ClientHello
    /// will include a `pre_shared_key` extension offering this ticket.
    pub fn set_psk_ticket(&mut self, ticket: SessionTicketData) {
        self.psk_ticket = Some(ticket);
    }

    /// Set TLS 1.2 session ticket data for the ClientHello's `session_ticket`
    /// extension (0x0023).
    ///
    /// This is used when the session store contains a TLS 1.2 ticket. The
    /// ticket data is placed in the `session_ticket` extension (not in
    /// `pre_shared_key`), matching Chrome/BoringSSL behavior.
    pub fn set_tls12_session_ticket(&mut self, ticket_data: Vec<u8>) {
        self.tls12_session_ticket_data = Some(ticket_data);
    }

    /// Set a key log callback for SSLKEYLOGFILE output.
    ///
    /// When set, handshake and application traffic secrets are emitted at
    /// derivation time without storing any extra data.
    pub fn set_keylog_callback(&mut self, cb: Arc<dyn Fn(&str) + Send + Sync>) {
        self.keylog_callback = Some(cb);
    }

    // =======================================================================
    // Build Client EncryptedExtensions (ALPS)
    // =======================================================================

    /// Build the Client EncryptedExtensions handshake message for ALPS.
    ///
    /// This message is sent after receiving the server Finished and before
    /// the client Finished, per draft-vvv-tls-alps. It carries the client's
    /// application settings to the server. Note that real Chrome sends an EMPTY
    /// client-settings payload here (`Some(vec![])`), so `ext_data_len` is
    /// commonly 0; a non-empty payload is also supported for other clients.
    ///
    /// Returns `None` if ALPS was not negotiated by the server or no payload was
    /// configured (`alps_payload == None`).
    fn build_client_encrypted_extensions(&self) -> Option<Vec<u8>> {
        // Only send Client EE if the server negotiated ALPS
        let code_point = self.alps_code_point?;
        let alps_payload = self.alps_payload.as_ref()?;

        // Build the inner extensions block:
        //   extension_type(2) + extension_data_length(2) + extension_data(N)
        let ext_data_len = alps_payload.len();
        let extensions_len = 2 + 2 + ext_data_len; // type + data_len + data

        // Build the EncryptedExtensions body:
        //   extensions_length(2) + extensions
        let body_len = 2 + extensions_len;

        // Full handshake message:
        //   HandshakeType(1) = 0x08 + Length(3) + body
        let total_len = 4 + body_len;
        let mut msg = Vec::with_capacity(total_len);

        // Handshake header
        msg.push(handshake_type::ENCRYPTED_EXTENSIONS);
        let body_len_u32 = body_len as u32;
        msg.push((body_len_u32 >> 16) as u8);
        msg.push((body_len_u32 >> 8) as u8);
        msg.push(body_len_u32 as u8);

        // Extensions length
        msg.push((extensions_len >> 8) as u8);
        msg.push(extensions_len as u8);

        // Extension: application_settings
        msg.push((code_point >> 8) as u8);
        msg.push(code_point as u8);
        msg.push((ext_data_len >> 8) as u8);
        msg.push(ext_data_len as u8);
        msg.extend_from_slice(alps_payload);

        tracing::debug!(
            "Built Client EncryptedExtensions (ALPS, code_point=0x{code_point:04x}, \
             payload_len={ext_data_len}, total_len={total_len})"
        );

        Some(msg)
    }

    // =======================================================================
    // Build ClientHello
    // =======================================================================

    /// Build the initial ClientHello handshake message.
    ///
    /// Returns the complete handshake message bytes (type + length + body).
    /// The caller should wrap these in a TLS record and send to the server.
    ///
    /// After calling this, the state transitions to `WaitServerHello`.
    ///
    /// If a PSK ticket was set via [`Self::set_psk_ticket`], the ClientHello will
    /// include a `pre_shared_key` extension as the last extension, with a
    /// computed binder over the truncated transcript.
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        if self.state != Tls13State::Start {
            return Err(TlsError::HandshakeFailure(
                "build_client_hello called in wrong state".to_string(),
            ));
        }

        // ALPS advertisement in the ClientHello is DECOUPLED from the client's
        // settings payload. Real Chrome advertises `application_settings: h2` in
        // the ClientHello while sending an EMPTY client-settings payload in its
        // Client EncryptedExtensions (verified against a real Chrome capture). So:
        //   None        => no ALPS (e.g. the H1-only request path)
        //   Some(bytes) => advertise ALPS; `bytes` (possibly empty) becomes the
        //                  Client EncryptedExtensions payload.
        let mut profile_for_ch = self.profile.clone();
        if self.alps_payload.is_none() {
            profile_for_ch.alps_protocols = None;
        }
        if self.quic_mode {
            profile_for_ch.tls_min_version = TlsVersion::Tls13;
            profile_for_ch.tls_max_version = TlsVersion::Tls13;
            profile_for_ch.session_id_length = 0;

            let has_quic_tp = profile_for_ch
                .extensions
                .iter()
                .any(|ext| ext.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS);
            if !has_quic_tp {
                let insert_at = profile_for_ch
                    .extensions
                    .iter()
                    .position(|ext| {
                        matches!(
                            ext.extension_type,
                            ext_type::PADDING | ext_type::PRE_SHARED_KEY
                        )
                    })
                    .unwrap_or(profile_for_ch.extensions.len());
                profile_for_ch.extensions.insert(
                    insert_at,
                    ExtensionSpec {
                        extension_type: ext_type::QUIC_TRANSPORT_PARAMETERS,
                        source: ExtensionSource::Auto,
                    },
                );
            }
        }
        let alps_compatible = self
            .psk_ticket
            .as_ref()
            .is_none_or(|ticket| self.alps_allows_early_data(ticket));
        if !alps_compatible {
            // Remove the source as well as the Auto flag: RawBytes early_data
            // must not bypass a known settings mismatch.
            profile_for_ch
                .extensions
                .retain(|extension| extension.extension_type != ext_type::EARLY_DATA);
        }
        let mut ch_builder = ClientHelloBuilder::new(&profile_for_ch, &self.hostname);
        if let Some(ref ech_config) = self.ech_config_list {
            ch_builder = ch_builder.with_ech_config(ech_config.clone());
        }
        if let Some(ref ticket_data) = self.tls12_session_ticket_data {
            ch_builder = ch_builder.with_session_ticket_data(ticket_data.clone());
        }
        if let Some(ref params) = self.quic_transport_parameters {
            ch_builder = ch_builder.with_quic_transport_parameters(params.clone());
        }
        if alps_compatible
            && self
                .psk_ticket
                .as_ref()
                .is_some_and(|ticket| ticket.max_early_data_size > 0)
        {
            ch_builder = ch_builder.with_early_data();
        }
        if self.ech_config_list.is_some() {
            if let Some(ticket) = self.psk_ticket.as_ref() {
                ch_builder = ch_builder.with_psk_offer(
                    ticket.ticket.clone(),
                    ticket.obfuscated_ticket_age(),
                    ticket.resumption_psk.clone(),
                    ticket.hkdf_algorithm,
                    Vec::new(),
                );
            }
        }
        // Pre-calculate PSK extension length so padding accounts for it.
        let psk_extra_len = if let Some(ref ticket) = self.psk_ticket {
            crate::extensions::pre_shared_key::psk_extension_length(
                ticket.ticket.len(),
                ticket.hkdf_algorithm.hash_len(),
            )
        } else {
            0
        };
        let output = ch_builder.build_with_psk_hint(psk_extra_len)?;

        // Extract random (offset 6..38) and session_id from the built message
        let msg = &output.message;
        let mut random = [0u8; 32];
        random.copy_from_slice(&msg[6..38]);
        let sid_len = msg[38] as usize;
        let session_id = msg[39..39 + sid_len].to_vec();

        if self.quic_mode && sid_len != 0 {
            return Err(TlsError::HandshakeFailure(
                "QUIC ClientHello must use an empty legacy_session_id".to_string(),
            ));
        }

        self.client_random = Some(random);
        self.session_id = Some(session_id);
        self.key_pairs = output.key_shares;
        self.grease_values = Some(output.grease_values);
        self.extension_order = Some(output.shuffled_extensions);
        self.ech_grease_extension = output.ech_grease_extension;

        // Store ECH state from the build output.
        if output.ech_offered {
            self.ech_offered = true;
            self.ech_inner_hello = output.inner_hello;
            self.ech_retry_state = output.ech_retry_state;
            tracing::debug!("ECH: real ECH offered in ClientHello");
        }

        // If we have a PSK ticket, append the pre_shared_key extension
        let psk_ticket_clone = self.psk_ticket.clone();
        let final_msg = if let Some(ref ticket) = psk_ticket_clone {
            if output.ech_offered {
                self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?);
                output.message
            } else {
                self.append_psk_extension(output.message, ticket, None)?
            }
        } else {
            output.message
        };

        self.buffered_client_hello = Some(final_msg.clone());
        self.record_offered_extensions(&final_msg);

        self.state = Tls13State::WaitServerHello;
        if !self.quic_mode {
            if let Some((ticket, hello)) = self.early_data_offer() {
                let mut early_transcript = TranscriptHash::new(ticket.hkdf_algorithm);
                early_transcript.update(hello);
                let early_secret = pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?;
                let traffic_secret =
                    early_secret.derive_secret("c e traffic", &early_transcript.current_hash())?;
                let flight = EndOfEarlyDataFlight {
                    message: vec![5, 0, 0, 0],
                    aead_algorithm: ticket.aead_algorithm,
                    client_key: hkdf_expand_label(
                        ticket.hkdf_algorithm,
                        &traffic_secret,
                        "key",
                        &[],
                        ticket.aead_algorithm.key_len(),
                    )?,
                    client_iv: hkdf_expand_label(
                        ticket.hkdf_algorithm,
                        &traffic_secret,
                        "iv",
                        &[],
                        ticket.aead_algorithm.nonce_len(),
                    )?,
                };
                self.client_end_of_early_data = Some(flight);
            }
        }
        Ok(final_msg)
    }

    /// Remember which extension types the ClientHello we just sent carried.
    ///
    /// Replace CH1's offer with CH2's actual offer after HRR. Eligible current
    /// ECH inner fields join the outer set until rejection selects the outer.
    fn record_offered_extensions(&mut self, client_hello: &[u8]) {
        let Some(extensions) = client_hello_extensions(client_hello) else {
            // The message came from our own builder, so this is a local bug, not
            // a peer protocol violation — say so loudly but do not fail the
            // handshake on it. The check simply has nothing to compare against.
            tracing::warn!(
                "tls13.client_hello_unparseable — RFC 8446 §4.2 unsolicited-extension check is disabled for this handshake"
            );
            return;
        };
        self.offered_alpn_protocols = Some(
            extensions
                .iter()
                .find(|(kind, _)| *kind == ext_type::ALPN)
                .and_then(|(_, payload)| crate::extensions::alpn::parse_alpn_list_bytes(payload))
                .map(|protocols| protocols.into_iter().map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
        );
        self.offered_supported_versions = extensions
            .iter()
            .find(|(kind, _)| *kind == ext_type::SUPPORTED_VERSIONS)
            .map(|(_, payload)| payload.to_vec());
        let offered = extensions.into_iter().map(|(kind, _)| kind);
        let known = self.offered_extensions.insert(Vec::new());
        for extension_type in offered {
            if !known.contains(&extension_type) {
                known.push(extension_type);
            }
        }
        let inner = if self.hrr_received {
            self.hrr_inner_ch2.clone()
        } else {
            self.ech_inner_hello.clone()
        };
        if let Some(inner) = inner.filter(|_| self.ech_hrr_accepted != Some(false)) {
            if let Some(inner_types) = client_hello_offered_extensions(&inner) {
                let known = self.offered_extensions.get_or_insert_with(Vec::new);
                for extension_type in inner_types {
                    if !known.contains(&extension_type) {
                        known.push(extension_type);
                    }
                }
            }
        }
    }

    /// Reject a ServerHello extension that RFC 8446 does not allow there, or
    /// that answers something we never offered (RFC 8446 §4.2).
    ///
    /// Only for an ordinary ServerHello: a HelloRetryRequest may additionally
    /// carry `cookie` (which a client never offers) and the ECH
    /// accept-confirmation, and [`server_hello::parse_server_hello`] already
    /// restricts the HRR extension set.
    fn check_server_hello_extensions(&self, sh: &ServerHello) -> Result<()> {
        for &extension_type in &sh.extension_types {
            if !server_hello::server_hello_permits_extension(extension_type) {
                return Err(TlsError::local_alert(
                    AlertDescription::UnsupportedExtension,
                    format!(
                        "extension 0x{extension_type:04x} is not permitted in ServerHello                          (RFC 8446 §4.1.3)"
                    ),
                ));
            }
            if let Some(ref offered) = self.offered_extensions {
                if !offered.contains(&extension_type) {
                    return Err(TlsError::local_alert(
                        AlertDescription::UnsupportedExtension,
                        format!(
                            "server sent unsolicited ServerHello extension                              0x{extension_type:04x}"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Reject an EncryptedExtensions extension we never offered (RFC 8446 §4.2).
    fn check_encrypted_extension_offered(&self, extension_type: u16) -> Result<()> {
        let Some(ref offered) = self.offered_extensions else {
            return Ok(());
        };
        if offered.contains(&extension_type) {
            return Ok(());
        }
        Err(TlsError::local_alert(
            AlertDescription::UnsupportedExtension,
            format!("server sent unsolicited EncryptedExtensions extension 0x{extension_type:04x}"),
        ))
    }

    /// Append the `pre_shared_key` extension to a ClientHello message and compute
    /// the PSK binder.
    ///
    /// The `pre_shared_key` extension MUST be the last extension in the ClientHello
    /// (RFC 8446 Section 4.2.11). The binder is computed over a truncated transcript
    /// that includes the ClientHello up to (but not including) the binders list.
    fn append_psk_extension(
        &mut self,
        mut ch_msg: Vec<u8>,
        ticket: &SessionTicketData,
        transcript_prefix: Option<&TranscriptHash>,
    ) -> Result<Vec<u8>> {
        let hkdf_algo = ticket.hkdf_algorithm;
        let binder_len = hkdf_algo.hash_len();

        // Build the PSK extension with placeholder binder
        let identities = vec![PskIdentity {
            identity: ticket.ticket.clone(),
            obfuscated_ticket_age: ticket.obfuscated_ticket_age(),
        }];
        let (psk_ext_bytes, binder_value_offset_in_ext) =
            pre_shared_key::encode_psk_extension(&identities, binder_len);

        // We need to update the ClientHello's extensions length and body length
        // to include the PSK extension.
        //
        // ClientHello layout:
        //   [0]    = handshake type (0x01)
        //   [1..4] = body length (3 bytes)
        //   [4..6] = protocol version
        //   [6..38] = random
        //   [38]   = session_id_length
        //   ... cipher suites, compression, extensions ...
        //
        // The extensions length field is at (end_of_message - extensions_data_len - 2).
        // We need to find it and update it.

        // Current total message length
        let old_msg_len = ch_msg.len();

        // The extensions_data is the last part of the body. The extensions_length
        // field is 2 bytes right before the extensions data.
        // body_len = msg_len - 4 (handshake header)
        // We can find extensions_length at the end:
        // Since we're appending to the extensions, just update the two length fields.

        // Append PSK extension bytes to the message
        ch_msg.extend_from_slice(&psk_ext_bytes);
        let new_msg_len = ch_msg.len();
        let added_len = new_msg_len - old_msg_len;

        // Update body length (bytes 1..4, big-endian 24-bit)
        let new_body_len = new_msg_len - 4;
        ch_msg[1] = ((new_body_len >> 16) & 0xFF) as u8;
        ch_msg[2] = ((new_body_len >> 8) & 0xFF) as u8;
        ch_msg[3] = (new_body_len & 0xFF) as u8;

        // Update extensions length field.
        // The extensions_length is a 2-byte field right before the extensions data.
        // We need to find it by walking the ClientHello structure.
        let sid_len = ch_msg[38] as usize;
        let cs_start = 39 + sid_len;
        let cs_len = u16::from_be_bytes([ch_msg[cs_start], ch_msg[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = ch_msg[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;

        let old_ext_len =
            u16::from_be_bytes([ch_msg[ext_len_pos], ch_msg[ext_len_pos + 1]]) as usize;
        let new_ext_len = old_ext_len + added_len;
        ch_msg[ext_len_pos] = ((new_ext_len >> 8) & 0xFF) as u8;
        ch_msg[ext_len_pos + 1] = (new_ext_len & 0xFF) as u8;

        // Now compute the binder.
        // The truncated ClientHello is everything up to (not including) the binders list.
        // binders_size = 2 (binders list len) + 1 (binder len byte) + binder_len
        let binders_sz = pre_shared_key::binders_size(1, binder_len);
        let truncated_ch_len = new_msg_len - binders_sz;
        let truncated_ch = &ch_msg[..truncated_ch_len];

        // For CH2 after HRR, the binder covers the existing
        // message_hash(CH1) + HRR prefix followed by Truncate(CH2).
        let transcript_hash = if let Some(prefix) = transcript_prefix {
            let mut transcript = prefix.clone();
            transcript.update(truncated_ch);
            transcript.current_hash()
        } else {
            use aws_lc_rs::digest;
            let algo = match hkdf_algo {
                HkdfAlgorithm::Sha256 => &digest::SHA256,
                HkdfAlgorithm::Sha384 => &digest::SHA384,
            };
            digest::digest(algo, truncated_ch).as_ref().to_vec()
        };

        // Compute the PSK binder
        let binder = pre_shared_key::compute_psk_binder(
            hkdf_algo,
            &ticket.resumption_psk,
            &transcript_hash,
        )?;

        // Cache the early secret so we can use it in the key schedule
        // if the server accepts our PSK.
        self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
            hkdf_algo,
            &ticket.resumption_psk,
        )?);

        // Overwrite the placeholder binder with the real value.
        // The binder is located at: (start of psk extension in ch_msg) + binder_value_offset_in_ext
        let psk_ext_start_in_msg = old_msg_len;
        let binder_abs_offset = psk_ext_start_in_msg + binder_value_offset_in_ext;
        ch_msg[binder_abs_offset..binder_abs_offset + binder_len].copy_from_slice(&binder);

        tracing::debug!(
            binder_len = binder_len,
            ticket_len = ticket.ticket.len(),
            "tls13.psk_extension_appended",
        );

        Ok(ch_msg)
    }

    fn ech_hrr_psk_transcript_prefix(
        hkdf_algorithm: HkdfAlgorithm,
        inner_client_hello: &[u8],
        hello_retry_request: &[u8],
    ) -> Vec<u8> {
        let algorithm = match hkdf_algorithm {
            HkdfAlgorithm::Sha256 => &digest::SHA256,
            HkdfAlgorithm::Sha384 => &digest::SHA384,
        };
        let client_hello_hash = digest::digest(algorithm, inner_client_hello);
        let mut prefix =
            Vec::with_capacity(4 + client_hello_hash.as_ref().len() + hello_retry_request.len());
        prefix.push(handshake_type::MESSAGE_HASH);
        prefix.extend_from_slice(&[0, 0, client_hello_hash.as_ref().len() as u8]);
        prefix.extend_from_slice(client_hello_hash.as_ref());
        prefix.extend_from_slice(hello_retry_request);
        prefix
    }

    // =======================================================================
    // Process handshake records
    // =======================================================================

    /// Process a handshake record payload that may contain one or more
    /// handshake messages.
    ///
    /// Returns the action from the last significant message processed.
    pub fn process_handshake_record(&mut self, data: &[u8]) -> Result<HandshakeAction> {
        let mut pos = 0;
        let mut last_action = HandshakeAction::ContinueReading;

        while pos + 4 <= data.len() {
            let msg_type = data[pos];
            let length = ((data[pos + 1] as usize) << 16)
                | ((data[pos + 2] as usize) << 8)
                | (data[pos + 3] as usize);
            let msg_end = pos + 4 + length;

            if msg_end > data.len() {
                return Err(TlsError::UnexpectedMessage(
                    "truncated handshake message in record".to_string(),
                ));
            }

            let full_msg = &data[pos..msg_end];
            let payload = &data[pos + 4..msg_end];

            last_action = self.process_single_message(msg_type, full_msg, payload)?;
            pos = msg_end;
        }

        Ok(last_action)
    }

    /// Process a single handshake message.
    ///
    /// `full_msg` includes the 4-byte handshake header (for transcript hashing).
    /// `payload` is just the message body (after the header).
    fn process_single_message(
        &mut self,
        msg_type: u8,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        match (self.state, msg_type) {
            (Tls13State::WaitServerHello, handshake_type::SERVER_HELLO) => {
                self.process_server_hello(full_msg, payload)
            }
            (Tls13State::WaitEncryptedExtensions, handshake_type::ENCRYPTED_EXTENSIONS) => {
                self.process_encrypted_extensions(full_msg, payload)
            }
            (Tls13State::WaitCertificate, handshake_type::CERTIFICATE_REQUEST) => {
                // Server requests client authentication (RFC 8446 §4.3.2).
                // We don't support client certificates, so remember the request
                // context and later send an empty Certificate message as required
                // by RFC 8446 §4.4.2.
                self.client_certificate_request_context =
                    Some(parse_certificate_request_context(payload)?);
                if let Some(ref mut transcript) = self.transcript {
                    transcript.update(full_msg);
                }
                tracing::debug!(
                    "tls13.certificate_request_received — will send empty client certificate"
                );
                Ok(HandshakeAction::ContinueReading)
            }
            (Tls13State::WaitCertificate, handshake_type::CERTIFICATE) => {
                self.process_certificate(full_msg, payload)
            }
            (Tls13State::WaitCertificate, handshake_type::COMPRESSED_CERTIFICATE) => {
                self.process_compressed_certificate(full_msg, payload)
            }
            (Tls13State::WaitCertificateVerify, handshake_type::CERTIFICATE_VERIFY) => {
                self.process_certificate_verify(full_msg, payload)
            }
            (Tls13State::WaitFinished, handshake_type::FINISHED) => {
                self.process_finished(full_msg, payload)
            }
            _ => Err(TlsError::UnexpectedMessage(format!(
                "unexpected message type 0x{msg_type:02x} in state {:?}",
                self.state
            ))),
        }
    }

    // =======================================================================
    // ServerHello processing
    // =======================================================================

    fn check_server_hello_payload_lengths(&self, payload: &[u8], sh: &ServerHello) -> Result<()> {
        // Container bounds are established by parse_server_hello. Validate
        // payloads after offer checks so an unsolicited extension keeps priority.
        let mut block = payload.get(40 + sh.session_id.len()..).unwrap_or_default();
        let nss = self.profile.tls_client_hello_style
            == crate::profile::types::TlsClientHelloStyle::FirefoxNss;
        while !block.is_empty() {
            let kind = u16::from_be_bytes([block[0], block[1]]);
            let length = u16::from_be_bytes([block[2], block[3]]) as usize;
            let data = &block[4..4 + length];
            block = &block[4 + length..];
            let alert = match kind {
                ext_type::KEY_SHARE if data.len() < 4 => Some(if nss {
                    AlertDescription::IllegalParameter
                } else {
                    AlertDescription::DecodeError
                }),
                ext_type::KEY_SHARE => {
                    let expected = 4 + u16::from_be_bytes([data[2], data[3]]) as usize;
                    if expected > data.len() {
                        Some(if nss {
                            AlertDescription::IllegalParameter
                        } else {
                            AlertDescription::DecodeError
                        })
                    } else if expected < data.len() {
                        Some(if nss {
                            AlertDescription::HandshakeFailure
                        } else {
                            AlertDescription::DecodeError
                        })
                    } else {
                        None
                    }
                }
                ext_type::PRE_SHARED_KEY if data.len() != 2 => Some(if nss && data.len() > 2 {
                    AlertDescription::HandshakeFailure
                } else {
                    AlertDescription::DecodeError
                }),
                _ => None,
            };
            if let Some(alert) = alert {
                return Err(TlsError::local_alert(
                    alert,
                    format!("ServerHello extension 0x{kind:04x} has invalid payload length"),
                ));
            }
        }
        Ok(())
    }

    fn process_server_hello(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        let (version, selected_extension) = server_hello::detect_version_for_style(
            full_msg,
            self.profile.tls_client_hello_style,
            self.hrr_received,
        )?;
        let sh = server_hello::parse_server_hello(payload)?;

        if version != 0x0304 || !selected_extension {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "server did not select TLS 1.3 with supported_versions",
            ));
        }

        // Browser stacks use different legacy-field rules for both SH and HRR.
        let session_id_mismatch = self
            .session_id
            .as_deref()
            .is_some_and(|session_id| sh.session_id != session_id);
        let field_alert = match self.profile.tls_client_hello_style {
            crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl => {
                (sh.legacy_version != 0x0303 || sh.compression_method != 0 || session_id_mismatch)
                    .then_some(AlertDescription::DecodeError)
            }
            crate::profile::types::TlsClientHelloStyle::FirefoxNss => {
                if sh.legacy_version >= 0x0304 || sh.compression_method != 0 {
                    Some(AlertDescription::IllegalParameter)
                } else if sh.legacy_version == 0x0300 {
                    Some(AlertDescription::ProtocolVersion)
                } else {
                    session_id_mismatch.then_some(AlertDescription::IllegalParameter)
                }
            }
            _ => None,
        };
        if let Some(alert) = field_alert {
            return Err(TlsError::local_alert(
                alert,
                "TLS 1.3 ServerHello has invalid browser-stack fixed fields",
            ));
        }

        // Check the serialized offer before deriving keys or answering HRR.
        // RawBytes may override the versions generated from the profile.
        if self.offered_extensions.is_some() {
            let versions = self.offered_supported_versions.as_deref().ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::UnsupportedExtension,
                    "server selected supported_versions without a client offer",
                )
            })?;
            if !crate::extensions::supported_versions::parse_client_versions(versions)
                .is_some_and(|versions| versions.contains(&sh.negotiated_version()))
            {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "server selected a TLS version absent from the actual ClientHello offer",
                ));
            }
        }

        // RFC 8446 §4.1.3: compression_method MUST be 0
        if sh.compression_method != 0 {
            return Err(TlsError::HandshakeFailure(format!(
                "ServerHello compression_method must be 0, got {}",
                sh.compression_method,
            )));
        }

        // RFC 8446 §4.1.3: legacy_session_id_echo MUST match
        if let Some(ref our_session_id) = self.session_id {
            if sh.session_id != *our_session_id {
                return Err(TlsError::HandshakeFailure(
                    "ServerHello session_id does not match ClientHello".to_string(),
                ));
            }
        }

        // Determine cipher suite and algorithms
        let (hkdf_algo, aead_algo) = cipher_suite_info(sh.cipher_suite)?;

        // RFC 8446 §4.2.1: server MUST select a cipher suite from the client's list
        if !self.profile.cipher_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "server selected cipher suite 0x{:04x} not offered by client",
                    sh.cipher_suite,
                ),
            ));
        }

        // RFC 8446 §4.1.4: after HRR, cipher suite MUST be retained
        if self.hrr_received {
            if let Some(prev_suite) = self.cipher_suite {
                if prev_suite != sh.cipher_suite {
                    return Err(TlsError::local_alert(
                        AlertDescription::IllegalParameter,
                        format!(
                            "ServerHello cipher suite 0x{:04x} differs from HRR 0x{:04x}",
                            sh.cipher_suite, prev_suite,
                        ),
                    ));
                }
            }
        }

        self.cipher_suite = Some(sh.cipher_suite);
        self.hkdf_algorithm = Some(hkdf_algo);
        self.aead_algorithm = Some(aead_algo);

        if sh.is_hello_retry_request {
            return self.process_hello_retry_request(full_msg, &sh, hkdf_algo);
        }

        // RFC 8446 §4.1.3 / §4.2: the ServerHello may only carry the extensions
        // that establish the cryptographic context, and only ones we offered.
        if self.ech_hrr_accepted == Some(false) && sh.extensions.selected_psk_identity.is_some() {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "ECH-rejected outer handshake cannot select an inner PSK",
            ));
        }
        self.check_server_hello_extensions(&sh)?;
        self.check_server_hello_payload_lengths(payload, &sh)?;

        // Check if server accepted our PSK
        if let Some(selected_identity) = sh.extensions.selected_psk_identity {
            if self.psk_ticket.is_some() && selected_identity == 0 {
                // RFC 8446 §4.2.11: PSK cipher suite hash MUST be compatible
                if let Some(ref ticket) = self.psk_ticket {
                    if ticket.hkdf_algorithm != hkdf_algo {
                        return Err(TlsError::local_alert(
                            AlertDescription::IllegalParameter,
                            format!(
                                "server selected PSK but cipher suite hash {:?} does not match \
                             ticket hash {:?}",
                                hkdf_algo, ticket.hkdf_algorithm,
                            ),
                        ));
                    }
                }
            } else {
                let alert = if self.profile.tls_client_hello_style
                    == crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                {
                    AlertDescription::UnknownPskIdentity
                } else {
                    AlertDescription::IllegalParameter
                };
                return Err(TlsError::local_alert(
                    alert,
                    format!(
                        "server selected unavailable PSK identity {}",
                        selected_identity,
                    ),
                ));
            }
        }

        // Normal ServerHello — update transcript and derive keys.

        if self.hrr_received {
            // After HRR: the transcript already contains message_hash(CH1) + HRR + CH2.
            // Just add the real ServerHello to the existing transcript.
            tracing::debug!(
                "Processing ServerHello after HRR (cipher_suite=0x{:04x})",
                sh.cipher_suite
            );
            if let Some(ref mut transcript) = self.transcript {
                transcript.update(full_msg);
            }
        } else {
            // First ServerHello (no HRR): initialize transcript with CH + SH.
            let mut transcript = TranscriptHash::new(hkdf_algo);
            if let Some(ref ch_bytes) = self.buffered_client_hello {
                transcript.update(ch_bytes);
            }
            transcript.update(full_msg);
            self.transcript = Some(transcript);
            self.buffered_client_hello = None;
        }

        // --- ECH acceptance detection (RFC 9849 Section 7.2) ---
        //
        // If real ECH was offered, check if the server accepted it by
        // verifying that ServerHello.random[24..32] matches the ECH
        // accept_confirmation computed with the inner CH transcript.
        if self.ech_offered && self.ech_hrr_accepted != Some(false) {
            if let Some(ref inner_hello) = self.ech_inner_hello {
                let accepted =
                    self.check_ech_acceptance(hkdf_algo, inner_hello, full_msg, &sh.random)?;

                if let Some(hrr_accepted) = self.ech_hrr_accepted {
                    if accepted != hrr_accepted {
                        return Err(TlsError::local_alert(
                            AlertDescription::IllegalParameter,
                            "server changed ECH acceptance across HelloRetryRequest",
                        ));
                    }
                }

                if accepted {
                    self.ech_accepted = true;
                    tracing::info!("ECH: server accepted — switching to inner CH transcript");

                    if self.hrr_received {
                        // HRR + ECH accepted: rebuild the transcript using inner CH.
                        // Transcript = message_hash(inner_CH1) + HRR + inner_CH2 + SH
                        let mut transcript = TranscriptHash::new(hkdf_algo);
                        transcript.update(inner_hello);
                        transcript.replace_with_message_hash();

                        if let Some(ref hrr_bytes) = self.hrr_raw_bytes {
                            transcript.update(hrr_bytes);
                        }
                        if let Some(ref ch2_bytes) = self.hrr_inner_ch2 {
                            transcript.update(ch2_bytes);
                        }
                        transcript.update(full_msg);
                        self.transcript = Some(transcript);
                        self.buffered_client_hello = None;
                    } else {
                        let mut transcript = TranscriptHash::new(hkdf_algo);
                        transcript.update(inner_hello);
                        transcript.update(full_msg);
                        self.transcript = Some(transcript);
                        self.buffered_client_hello = None;
                    }
                } else {
                    tracing::debug!("ECH: server did not accept — continuing with outer CH");
                }
            }
        }

        if self.ech_accepted {
            if let Some(active) = self
                .hrr_inner_ch2
                .as_ref()
                .or(self.ech_inner_hello.as_ref())
                .cloned()
            {
                self.record_offered_extensions(&active);
            }
        }

        // If ECH was not accepted (or not offered), transcript is already set
        // from the outer CH above.
        if self.ech_offered && !self.ech_accepted && sh.extensions.selected_psk_identity.is_some() {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "ECH-rejected outer handshake cannot resume an inner PSK",
            ));
        }

        let shared_secret = self.compute_shared_secret(&sh)?;
        self.psk_accepted = sh.extensions.selected_psk_identity.is_some();
        if self.psk_accepted {
            tracing::debug!(
                cipher_suite = format_args!("0x{:04x}", sh.cipher_suite),
                "tls13.psk_accepted - session resumption"
            );
        }

        // Derive handshake keys via TLS 1.3 key schedule
        // If PSK was accepted, use the cached Early Secret from the PSK
        let hs_keys = self.derive_handshake_keys(hkdf_algo, aead_algo, &shared_secret)?;

        self.state = Tls13State::WaitEncryptedExtensions;
        Ok(HandshakeAction::InstallHandshakeKeys(hs_keys))
    }

    // =======================================================================
    // HelloRetryRequest processing
    // =======================================================================

    fn process_hello_retry_request(
        &mut self,
        full_msg: &[u8],
        sh: &ServerHello,
        hkdf_algo: HkdfAlgorithm,
    ) -> Result<HandshakeAction> {
        if self.hrr_received {
            return Err(TlsError::local_alert(
                AlertDescription::UnexpectedMessage,
                "received second HelloRetryRequest",
            ));
        }

        if sh.legacy_version != 0x0303
            && self.profile.tls_client_hello_style
                != crate::profile::types::TlsClientHelloStyle::FirefoxNss
        {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "HRR legacy_version must be 0x0303, got 0x{:04x}",
                    sh.legacy_version
                ),
            ));
        }
        if sh.extensions.supported_version != Some(0x0304) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "HRR must contain supported_versions selecting TLS 1.3",
            ));
        }

        if self.ech_offered {
            let accepted = if let Some(expected) = sh.extensions.ech_confirmation {
                let inner_hello = self.ech_inner_hello.as_deref().ok_or_else(|| {
                    TlsError::local_alert(
                        AlertDescription::InternalError,
                        "real ECH was offered without a saved inner ClientHello",
                    )
                })?;
                self.check_ech_hrr_acceptance(hkdf_algo, inner_hello, full_msg, &expected)?
            } else {
                false
            };
            self.ech_hrr_accepted = Some(accepted);
            if !accepted {
                self.psk_ticket = None;
                self.early_secret_from_psk = None;
                self.offered_extensions = None;
            }
        } else if sh.extensions.ech_confirmation.is_some() {
            return Err(TlsError::local_alert(
                AlertDescription::UnsupportedExtension,
                "server sent ECH HRR confirmation without a real ECH offer",
            ));
        }

        // Both BoringSSL and NSS omit incompatible PSKs from CH2. Discard the
        // cached secret as well so only the selected hash drives the retry.
        if self
            .psk_ticket
            .as_ref()
            .is_some_and(|ticket| ticket.hkdf_algorithm != hkdf_algo)
        {
            self.psk_ticket = None;
            self.early_secret_from_psk = None;
        }

        self.hrr_received = true;
        self.client_end_of_early_data = None;
        self.hrr_raw_bytes = Some(full_msg.to_vec());
        tracing::debug!(
            "HRR received: selected_group={:?}, cookie={}",
            sh.extensions.selected_group,
            sh.extensions.cookie.is_some()
        );

        // Initialize transcript with buffered CH1, then replace with message_hash
        let mut transcript = TranscriptHash::new(hkdf_algo);
        if let Some(ref ch_bytes) = self.buffered_client_hello {
            transcript.update(ch_bytes);
        }
        // Replace CH1 hash with synthetic message_hash (RFC 8446 Section 4.4.1)
        transcript.replace_with_message_hash();
        // Add the HRR message to transcript
        transcript.update(full_msg);
        self.transcript = Some(transcript);

        let replace_key_share = if let Some(required_group) = sh.extensions.selected_group {
            if !self.profile.supported_groups.contains(&required_group) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "HRR requested group not offered in supported_groups: 0x{required_group:04x}"
                    ),
                ));
            }
            if self
                .key_pairs
                .iter()
                .any(|key_pair| key_pair.group.code_point() == required_group)
            {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "HRR requested group already present in CH1 key_share: 0x{required_group:04x}"
                    ),
                ));
            }

            let kx_group = KxGroup::from_code_point(required_group).ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!("HRR requested unsupported group: 0x{required_group:04x}"),
                )
            })?;
            self.key_pairs = vec![kx::generate_key_pair(kx_group)?];
            true
        } else {
            false
        };

        if !replace_key_share && sh.extensions.cookie.is_none() {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "HRR would not change the second ClientHello",
            ));
        }

        // Build CH2: use the original random and session_id, with new key_share
        // and optional cookie from HRR.
        let ch2 = self.build_client_hello_retry(&sh.extensions.cookie, replace_key_share)?;

        // Feed CH2 into transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&ch2);
        }
        self.buffered_client_hello = None;

        self.state = Tls13State::WaitServerHello;
        Ok(HandshakeAction::RetryClientHello(ch2))
    }

    /// Build the second ClientHello (CH2) after HRR.
    ///
    /// Preserves the original random and session_id, but replaces key_share
    /// with the newly generated key pair and adds cookie if provided.
    fn build_client_hello_retry(
        &mut self,
        cookie: &Option<Vec<u8>>,
        replace_key_share: bool,
    ) -> Result<Vec<u8>> {
        let random = self.client_random.ok_or_else(|| {
            TlsError::HandshakeFailure("missing client_random for HRR".to_string())
        })?;
        let session_id = self
            .session_id
            .clone()
            .ok_or_else(|| TlsError::HandshakeFailure("missing session_id for HRR".to_string()))?;

        let mut profile_for_ch = self.profile.clone();
        // Same ALPS gate as the initial ClientHello: only `None` suppresses ALPS;
        // `Some(empty)` still advertises it (Chrome sends empty client settings).
        if self.alps_payload.is_none() {
            profile_for_ch.alps_protocols = None;
        }
        if self.quic_mode {
            profile_for_ch.tls_min_version = TlsVersion::Tls13;
            profile_for_ch.tls_max_version = TlsVersion::Tls13;
            profile_for_ch.session_id_length = 0;
            let has_quic_tp = profile_for_ch
                .extensions
                .iter()
                .any(|ext| ext.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS);
            if !has_quic_tp {
                let insert_at = profile_for_ch
                    .extensions
                    .iter()
                    .position(|ext| {
                        matches!(
                            ext.extension_type,
                            ext_type::PADDING | ext_type::PRE_SHARED_KEY
                        )
                    })
                    .unwrap_or(profile_for_ch.extensions.len());
                profile_for_ch.extensions.insert(
                    insert_at,
                    ExtensionSpec {
                        extension_type: ext_type::QUIC_TRANSPORT_PARAMETERS,
                        source: ExtensionSource::Auto,
                    },
                );
            }
        }
        let ech_rejected = self.ech_hrr_accepted == Some(false);
        let retry_hostname = if ech_rejected {
            self.ech_rejection_public_name().ok_or_else(|| {
                TlsError::HandshakeFailure("missing ECH public_name for outer retry".into())
            })?
        } else {
            self.hostname.clone()
        };
        let mut builder = ClientHelloBuilder::new(&profile_for_ch, &retry_hostname)
            .with_random(random)
            .with_session_id(session_id);

        if let Some(ref grease) = self.grease_values {
            builder = builder.with_grease_values(grease.clone());
        }
        if let Some(ref extension_order) = self.extension_order {
            builder = builder.with_extension_order(extension_order.clone());
        }
        if let Some(ref ech_grease_extension) = self.ech_grease_extension {
            builder = builder.with_ech_grease_extension(ech_grease_extension.clone());
        }
        if ech_rejected {
            let first = self.buffered_client_hello.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailure("missing outer CH1 for ECH rejection".into())
            })?;
            builder = builder.with_ech_grease_extension(extract_ech_extension(first)?);
        } else if let Some(ref ech_config) = self.ech_config_list {
            builder = builder.with_ech_config(ech_config.clone());
        }
        if let Some(ref ticket_data) = self.tls12_session_ticket_data {
            builder = builder.with_session_ticket_data(ticket_data.clone());
        }
        if let Some(ref params) = self.quic_transport_parameters {
            builder = builder.with_quic_transport_parameters(params.clone());
        }
        if let Some(ref cookie_data) = cookie {
            builder = builder.with_cookie(cookie_data.clone());
        }
        if !ech_rejected && self.ech_retry_state.is_some() {
            if let Some(ticket) = self.psk_ticket.as_ref() {
                let inner_client_hello = self.ech_inner_hello.as_deref().ok_or_else(|| {
                    TlsError::HandshakeFailure(
                        "missing ClientHelloInner1 for ECH PSK HRR".to_string(),
                    )
                })?;
                let hello_retry_request = self.hrr_raw_bytes.as_deref().ok_or_else(|| {
                    TlsError::HandshakeFailure(
                        "missing HelloRetryRequest for ECH PSK binder".to_string(),
                    )
                })?;
                let transcript_prefix = Self::ech_hrr_psk_transcript_prefix(
                    ticket.hkdf_algorithm,
                    inner_client_hello,
                    hello_retry_request,
                );
                builder = builder.with_psk_offer(
                    ticket.ticket.clone(),
                    ticket.obfuscated_ticket_age(),
                    ticket.resumption_psk.clone(),
                    ticket.hkdf_algorithm,
                    transcript_prefix,
                );
            }
        }

        let ech_retry = if ech_rejected {
            None
        } else {
            self.ech_retry_state.as_mut()
        };
        let output = if replace_key_share {
            builder.build_retry_with_key_pairs(&self.key_pairs, ech_retry)?
        } else {
            builder.build_cookie_retry_with_key_pairs(&self.key_pairs, ech_retry)?
        };

        let ech_offered = output.ech_offered;
        if ech_offered {
            self.hrr_inner_ch2 = output.inner_hello;
        }

        let mut final_message = output.message;
        if let Some(ticket) = self.psk_ticket.clone() {
            if ech_offered {
                self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?);
            } else {
                let transcript_prefix = self.transcript.clone();
                final_message =
                    self.append_psk_extension(final_message, &ticket, transcript_prefix.as_ref())?;
            }
        }

        self.record_offered_extensions(&final_message);
        if let Some(inner_ch2) = self.hrr_inner_ch2.clone() {
            self.record_offered_extensions(&inner_ch2);
        }

        Ok(final_message)
    }

    // =======================================================================
    // EncryptedExtensions processing
    // =======================================================================

    fn process_encrypted_extensions(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Update transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse EncryptedExtensions
        // Format: extensions_length (2 bytes) + extensions
        if payload.len() < 2 {
            return Err(TlsError::local_alert(
                AlertDescription::DecodeError,
                "EncryptedExtensions too short",
            ));
        }

        let ext_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if 2 + ext_len != payload.len() {
            return Err(TlsError::local_alert(
                AlertDescription::DecodeError,
                "EncryptedExtensions length mismatch",
            ));
        }

        // Parse individual extensions
        let mut pos = 2;
        let ext_end = 2 + ext_len;
        let mut saw_quic_transport_params = false;
        let mut saw_early_data = false;
        let mut selected_alpn = None;
        let mut seen_extensions: Vec<u16> = Vec::new();
        while pos < ext_end {
            if pos + 4 > ext_end {
                return Err(TlsError::local_alert(
                    AlertDescription::DecodeError,
                    "truncated EncryptedExtensions extension header",
                ));
            }
            let extension_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_data_len > ext_end {
                return Err(TlsError::local_alert(
                    AlertDescription::DecodeError,
                    "truncated EncryptedExtensions extension payload",
                ));
            }

            // RFC 8446 §4.2: at most one extension of each type per block, and
            // never an extension the client did not offer.
            if seen_extensions.contains(&extension_type) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!("duplicate EncryptedExtensions extension 0x{extension_type:04x}"),
                ));
            }
            seen_extensions.push(extension_type);
            self.check_encrypted_extension_offered(extension_type)?;

            let ext_data = &payload[pos..pos + ext_data_len];

            match extension_type {
                // ALPN (0x0010): extract the server's selected protocol
                ext_type::ALPN => {
                    let selected = crate::extensions::alpn::parse_server_alpn_bytes(ext_data)
                        .ok_or_else(|| {
                            TlsError::local_alert(
                                AlertDescription::DecodeError,
                                "invalid server ALPN protocol list",
                            )
                        })?;
                    let offered = match &self.offered_alpn_protocols {
                        Some(protocols) => protocols
                            .iter()
                            .any(|protocol| protocol.as_slice() == selected),
                        None => self
                            .profile
                            .alpn_protocols
                            .iter()
                            .any(|protocol| protocol.as_bytes() == selected),
                    };
                    if !offered {
                        return Err(TlsError::local_alert(
                            AlertDescription::IllegalParameter,
                            "server selected an unoffered ALPN protocol",
                        ));
                    }
                    selected_alpn = Some(selected);
                    self.negotiated_alpn = Some(String::from_utf8_lossy(selected).into_owned());
                }
                // ALPS: application_settings (old code point 0x4469, new 0x44CD)
                0x4469 | 0x44CD => {
                    tracing::debug!(
                        "Server negotiated ALPS (ext=0x{extension_type:04x}), payload_len={}",
                        ext_data.len()
                    );
                    self.server_alps_data = Some(ext_data.to_vec());
                    self.alps_code_point = Some(extension_type);
                }
                // ECH retry_configs (0xFE0D): server provides updated ECHConfigList
                0xFE0D => {
                    tracing::debug!("Server sent ECH retry_configs (len={})", ext_data.len());
                    self.ech_retry_configs = Some(ext_data.to_vec());
                }
                ext_type::EARLY_DATA => {
                    let nss = self.profile.tls_client_hello_style
                        == crate::profile::types::TlsClientHelloStyle::FirefoxNss;
                    if !ext_data.is_empty() {
                        return Err(TlsError::local_alert(
                            if nss {
                                AlertDescription::HandshakeFailure
                            } else {
                                AlertDescription::DecodeError
                            },
                            "server early_data extension must be empty",
                        ));
                    }
                    if !self.psk_accepted {
                        return Err(TlsError::local_alert(
                            if nss {
                                AlertDescription::IllegalParameter
                            } else {
                                AlertDescription::UnsupportedExtension
                            },
                            "server accepted early_data without resuming the offered PSK",
                        ));
                    }
                    saw_early_data = true;
                }
                // record_size_limit (0x001c) — RFC 8449. The server's receive
                // limit bounds the records *we* send once traffic keys are in
                // place; a value below 64 is a fatal illegal_parameter.
                ext_type::RECORD_SIZE_LIMIT => {
                    let limit = parse_peer_record_size_limit(ext_data)?;
                    tracing::debug!("Server record_size_limit: {limit}");
                    self.peer_record_size_limit = Some(limit);
                }
                ext_type::QUIC_TRANSPORT_PARAMETERS => {
                    let params = decode_transport_params(ext_data)?;
                    tracing::debug!(
                        count = params.parameters.len(),
                        "Server sent QUIC transport parameters"
                    );
                    self.peer_quic_transport_params = Some(params);
                    saw_quic_transport_params = true;
                }
                // Other extensions — acknowledged but not processed.
                _ => {}
            }

            pos += ext_data_len;
        }

        // Early data uses the ticket's complete parameters, whereas ordinary
        // PSK resumption only requires a compatible cipher-suite hash.
        if saw_early_data {
            let ticket = self.psk_ticket.as_ref().ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::UnsupportedExtension,
                    "server accepted early_data without an offered session ticket",
                )
            })?;
            if self.cipher_suite != Some(ticket.cipher_suite) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "server changed the cipher suite while accepting early_data",
                ));
            }
            if ticket.alpn.as_deref().map(str::as_bytes) != selected_alpn {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "server changed ALPN while accepting early_data",
                ));
            }
            if self.server_alps_data.is_some() {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "server renegotiated ALPS while accepting early_data",
                ));
            }
        }

        let used_alpn = self
            .offered_extensions
            .as_ref()
            .map_or(!self.profile.alpn_protocols.is_empty(), |offered| {
                offered.contains(&ext_type::ALPN)
            });
        if self.quic_mode && used_alpn && self.negotiated_alpn.is_none() {
            return Err(TlsError::local_alert(
                AlertDescription::NoApplicationProtocol,
                "QUIC server did not negotiate the offered ALPN protocols",
            ));
        }

        if self.quic_mode && !saw_quic_transport_params {
            return Err(TlsError::HandshakeFailure(
                "server did not provide QUIC transport parameters".to_string(),
            ));
        }

        self.early_data_accepted = saw_early_data;
        if !saw_early_data {
            self.client_end_of_early_data = None;
        }
        if saw_early_data {
            tracing::debug!("Server accepted TLS early_data");
        }

        // When PSK is accepted, the server skips Certificate/CertificateVerify
        // and goes directly to Finished (RFC 8446 Section 2.2).
        if self.psk_accepted {
            self.state = Tls13State::WaitFinished;
            tracing::debug!("tls13.psk_resumption — skipping certificate");
        } else {
            self.state = Tls13State::WaitCertificate;
        }
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // Certificate processing
    // =======================================================================

    fn process_certificate(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        // Update transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse TLS 1.3 Certificate message
        // Format:
        //   certificate_request_context<0..255>
        //   certificate_list<0..2^24-1>
        //     CertificateEntry:
        //       cert_data<1..2^24-1>
        //       extensions<0..2^16-1>
        self.server_certificates = parse_certificate_message(payload)?;

        if self.server_certificates.is_empty() {
            return Err(TlsError::CertificateError(
                "server sent empty certificate chain".to_string(),
            ));
        }

        self.state = Tls13State::WaitCertificateVerify;
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // CompressedCertificate processing (RFC 8879)
    // =======================================================================

    fn process_compressed_certificate(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Update transcript with the CompressedCertificate message
        // (transcript uses the compressed form, not the decompressed one)
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse CompressedCertificate:
        //   algorithm (2 bytes)
        //   uncompressed_length (3 bytes)
        //   compressed_certificate_message<1..2^24-1>
        if payload.len() < 5 {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate too short".to_string(),
            ));
        }

        let algorithm = u16::from_be_bytes([payload[0], payload[1]]);
        let uncompressed_length =
            ((payload[2] as usize) << 16) | ((payload[3] as usize) << 8) | (payload[4] as usize);

        if payload.len() < 8 {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate truncated".to_string(),
            ));
        }
        let compressed_len =
            ((payload[5] as usize) << 16) | ((payload[6] as usize) << 8) | (payload[7] as usize);

        if 8 + compressed_len > payload.len() {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate data extends past message".to_string(),
            ));
        }
        let compressed_data = &payload[8..8 + compressed_len];

        // Decompress
        let decompressed = decompress_certificate(algorithm, compressed_data, uncompressed_length)?;

        // Parse the decompressed Certificate message
        self.server_certificates = parse_certificate_message(&decompressed)?;

        if self.server_certificates.is_empty() {
            return Err(TlsError::CertificateError(
                "server sent empty certificate chain".to_string(),
            ));
        }

        self.state = Tls13State::WaitCertificateVerify;
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // CertificateVerify processing
    // =======================================================================

    /// Enforce RFC 8446 §4.4.3 on the CertificateVerify signature scheme.
    ///
    /// Two rules, both independent of whether the certificate itself is trusted:
    ///
    /// * The scheme MUST be one the client advertised in `signature_algorithms`.
    ///   Completing a handshake on an algorithm we never offered is a protocol
    ///   violation and — for a client whose whole point is to look like a
    ///   specific browser — a contradiction the server can see.
    /// * `rsa_pkcs1_*` MUST NOT appear here. The profiles advertise those code
    ///   points because TLS 1.3 still allows PKCS#1 v1.5 signatures *on
    ///   certificates*; the CertificateVerify message itself is PSS-only.
    fn check_certificate_verify_scheme(&self, scheme: u16) -> Result<()> {
        // rsa_pkcs1_sha1 / _sha256 / _sha384 / _sha512
        if matches!(scheme, 0x0201 | 0x0401 | 0x0501 | 0x0601) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "rsa_pkcs1 scheme 0x{scheme:04x} is not allowed in CertificateVerify (RFC 8446 §4.4.3)"
                ),
            ));
        }

        // A profile with no advertised signature algorithms tells us nothing to
        // compare against; the ClientHello would be malformed anyway.
        if self.profile.signature_algorithms.is_empty() {
            return Ok(());
        }
        if !self.profile.signature_algorithms.contains(&scheme) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "server signed CertificateVerify with scheme 0x{scheme:04x}, which the client did not offer"
                ),
            ));
        }
        Ok(())
    }

    fn process_certificate_verify(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Get transcript hash BEFORE adding CertificateVerify to transcript
        // (CertificateVerify signs Hash(CH..Cert), not including itself)
        let transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        // Update transcript with CertificateVerify
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse CertificateVerify: signature_scheme (2) + signature<0..2^16-1>
        if payload.len() < 4 {
            return Err(TlsError::UnexpectedMessage(
                "CertificateVerify too short".to_string(),
            ));
        }
        let sig_scheme = u16::from_be_bytes([payload[0], payload[1]]);
        let sig_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if 4 + sig_len > payload.len() {
            return Err(TlsError::UnexpectedMessage(
                "CertificateVerify signature length mismatch".to_string(),
            ));
        }
        let signature = &payload[4..4 + sig_len];

        // Which algorithm the server was allowed to sign with is a protocol
        // rule, not a trust decision — it holds even when certificate
        // verification is switched off.
        self.check_certificate_verify_scheme(sig_scheme)?;

        if self.verification_policy.is_insecure() {
            self.state = Tls13State::WaitFinished;
            return Ok(HandshakeAction::ContinueReading);
        }

        // Verify the signature against the leaf certificate's public key
        let leaf_cert = &self.server_certificates[0];
        self.verification_policy.verify_certificate_verify(
            sig_scheme,
            leaf_cert,
            &transcript_hash,
            signature,
        )?;

        // Verify the certificate chain.
        //
        // When ECH was offered and rejected, the server answered the *outer*
        // ClientHello, whose SNI is the ECH config's `public_name` — so that is
        // the identity it presents a certificate for, and the identity RFC 9849
        // §6.1.6 says to authenticate. Checking the true hostname here would
        // fail on a name the server never claimed, turning an ECH rejection into
        // a misleading certificate error and discarding the `retry_configs` that
        // make recovery possible. Acceptance is already known at this point: it
        // is decided from ServerHello.random, which arrives before Certificate.
        let verify_name = self.ech_rejection_public_name();
        let verify_name = verify_name.as_deref().unwrap_or(&self.hostname);
        self.verification_policy.verify_certificate_chain(
            &self.server_certificates,
            verify_name,
            std::time::SystemTime::now(),
            self.custom_ca_anchors.as_deref().map(|v| v.as_slice()),
        )?;

        self.state = Tls13State::WaitFinished;
        Ok(HandshakeAction::ContinueReading)
    }

    /// The `public_name` the server must be authenticated as, when ECH was
    /// offered and rejected.
    ///
    /// Returns `None` whenever the true hostname is the right identity: ECH was
    /// not offered, ECH was accepted (the server answered the *inner*
    /// ClientHello), or the config that would name it is unavailable.
    pub(crate) fn ech_rejection_public_name(&self) -> Option<String> {
        if !self.ech_offered || self.ech_accepted {
            return None;
        }
        let public_name = self.ech_retry_state.as_ref()?.config.public_name.clone();
        if public_name.is_empty() {
            return None;
        }
        tracing::debug!(
            public_name = %public_name,
            "ech.rejected — authenticating the public_name instead of the true host"
        );
        Some(public_name)
    }

    // =======================================================================
    // Finished processing
    // =======================================================================

    fn process_finished(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        let hkdf_algo = self.hkdf_algorithm.unwrap();
        let aead_algo = self.aead_algorithm.unwrap();

        // --- Verify server Finished ---
        // verify_data = HMAC(finished_key, Transcript-Hash(CH..CV))
        let transcript_hash_before_sf = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        let server_hs_secret = self.server_hs_traffic_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("missing server_hs_traffic_secret".to_string())
        })?;

        let expected_verify_data =
            compute_finished_verify_data(hkdf_algo, server_hs_secret, &transcript_hash_before_sf)?;

        if payload != expected_verify_data.as_slice() {
            return Err(TlsError::HandshakeFailure(
                "server Finished verify_data mismatch".to_string(),
            ));
        }

        // Update transcript with server Finished
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // --- Derive Master Secret ---
        let handshake_secret = self
            .handshake_secret
            .take()
            .ok_or_else(|| TlsError::HandshakeFailure("missing handshake_secret".to_string()))?;

        // Master Secret = Derive-Next(Handshake Secret, 0)
        let zero_ikm = vec![0u8; hkdf_algo.hash_len()];
        let master_secret = handshake_secret.derive_next(&zero_ikm)?;

        // --- Derive application traffic secrets ---
        // Transcript-Hash(CH..SF) — includes server Finished
        let transcript_hash_ch_sf = self.transcript.as_ref().unwrap().current_hash();

        let client_app_secret =
            master_secret.derive_secret("c ap traffic", &transcript_hash_ch_sf)?;
        let server_app_secret =
            master_secret.derive_secret("s ap traffic", &transcript_hash_ch_sf)?;
        // Exporter master secret (RFC 8446 §7.5): Derive-Secret(master, "exp
        // master", CH..server Finished). Computed here while both the master
        // secret and the CH..SF transcript hash are in hand; emits nothing on
        // the wire, so it has no fingerprint impact.
        let exporter_master_secret =
            master_secret.derive_secret("exp master", &transcript_hash_ch_sf)?;

        // Emit application traffic secrets via keylog callback
        if let Some(ref cb) = self.keylog_callback {
            if let Some(cr) = self.client_random {
                let cr_hex = to_hex(&cr);
                cb(&format!(
                    "CLIENT_TRAFFIC_SECRET_0 {cr_hex} {}",
                    to_hex(&client_app_secret)
                ));
                cb(&format!(
                    "SERVER_TRAFFIC_SECRET_0 {cr_hex} {}",
                    to_hex(&server_app_secret)
                ));
            }
        }

        // Derive application traffic keys
        let client_key = hkdf_expand_label(
            hkdf_algo,
            &client_app_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let client_iv = hkdf_expand_label(
            hkdf_algo,
            &client_app_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;
        let server_key = hkdf_expand_label(
            hkdf_algo,
            &server_app_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let server_iv = hkdf_expand_label(
            hkdf_algo,
            &server_app_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;

        // TCP closes the early-key epoch before the handshake-key client flight.
        // QUIC signals this transition through packet encryption levels instead.
        let client_end_of_early_data = if self.early_data_accepted && !self.quic_mode {
            let flight = self.client_end_of_early_data.take().ok_or_else(|| {
                TlsError::HandshakeFailure("missing TCP early-data write keys".into())
            })?;
            self.transcript.as_mut().unwrap().update(&flight.message);
            Some(flight)
        } else {
            None
        };

        // --- Build Client EncryptedExtensions (ALPS) ---
        // If the server negotiated ALPS, we must send a Client EE message
        // *before* the client Finished, and include it in the transcript.
        let client_ee = self.build_client_encrypted_extensions();

        // If ALPS was negotiated, update transcript: CH..SF..CEE
        if let Some(ref cee_msg) = client_ee {
            if let Some(ref mut transcript) = self.transcript {
                transcript.update(cee_msg);
            }
        }

        // A client without a suitable certificate must still answer a
        // handshake-time CertificateRequest with an empty Certificate message.
        let client_certificate = self
            .client_certificate_request_context
            .as_deref()
            .map(build_empty_client_certificate);
        if let Some(ref certificate_msg) = client_certificate {
            if let Some(ref mut transcript) = self.transcript {
                transcript.update(certificate_msg);
            }
        }

        // --- Compute client Finished ---
        let client_hs_secret = self.client_hs_traffic_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("missing client_hs_traffic_secret".to_string())
        })?;

        // Transcript for client Finished = CH..SF[..EOED][..CEE][..Certificate].
        let transcript_for_cf = self.transcript.as_ref().unwrap().current_hash();
        let client_verify_data =
            compute_finished_verify_data(hkdf_algo, client_hs_secret, &transcript_for_cf)?;

        // Build client Finished handshake message
        let mut client_finished = Vec::with_capacity(4 + client_verify_data.len());
        client_finished.push(handshake_type::FINISHED);
        let len = client_verify_data.len() as u32;
        client_finished.push((len >> 16) as u8);
        client_finished.push((len >> 8) as u8);
        client_finished.push(len as u8);
        client_finished.extend_from_slice(&client_verify_data);

        // --- Derive Resumption Master Secret ---
        // Update transcript with client Finished for RMS computation
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&client_finished);
        }
        let transcript_hash_ch_cf = self.transcript.as_ref().unwrap().current_hash();
        let resumption_master_secret =
            master_secret.derive_secret("res master", &transcript_hash_ch_cf)?;

        self.state = Tls13State::Connected;
        Ok(HandshakeAction::Complete(Box::new(HandshakeComplete {
            client_end_of_early_data,
            client_encrypted_extensions: client_ee,
            client_certificate,
            client_finished,
            traffic_secrets: TrafficSecrets {
                aead_algorithm: aead_algo,
                hkdf_algorithm: hkdf_algo,
                client_key,
                client_iv,
                server_key,
                server_iv,
                server_app_secret: server_app_secret.to_vec(),
                client_app_secret: client_app_secret.to_vec(),
                exporter_master_secret,
            },
            negotiated_alpn: self.negotiated_alpn.clone(),
            alps: self.effective_alps_state(),
            peer_record_size_limit: self.peer_record_size_limit,
            resumption_master_secret,
            negotiated_cipher_suite: self.cipher_suite.unwrap_or(0x1301),
            server_certificates: self.server_certificates.clone(),
            ech_retry_configs: self.ech_retry_configs.clone(),
            ech_accepted: self.ech_accepted,
            ech_offered: self.ech_offered,
            peer_quic_transport_params: self.peer_quic_transport_params.clone(),
            early_data_accepted: self.early_data_accepted,
            session_resumed: self.psk_accepted,
        })))
    }

    // =======================================================================
    // ECH acceptance detection
    // =======================================================================

    /// Check if the server accepted ECH by computing the accept_confirmation
    /// and comparing with ServerHello.random[24..32].
    ///
    /// Per RFC 9849 Section 7.2:
    ///
    /// ```text
    /// accept_confirmation = HKDF-Expand-Label(
    ///     HKDF-Extract(0, ClientHelloInner.random),
    ///     "ech accept confirmation",
    ///     Transcript-Hash(ClientHelloInner...ServerHello'),
    ///     8)
    /// ```
    ///
    /// where ServerHello' is ServerHello with random[24..32] zeroed before
    /// hashing. The secret is `HKDF-Extract(salt=0, IKM=ClientHelloInner.random)`
    /// — it is NOT the handshake secret and is independent of the ECDH/PSK
    /// secrets. The output is exactly 8 bytes (length 8 is encoded into the
    /// HKDF label, so this is not `derive_secret()[..8]`).
    fn check_ech_acceptance(
        &self,
        hkdf_algo: HkdfAlgorithm,
        inner_hello: &[u8],
        server_hello_msg: &[u8],
        server_random: &[u8; 32],
    ) -> Result<bool> {
        let hash_len = hkdf_algo.hash_len();

        // Build the RFC 9849 trial transcript. With HRR this is
        // message_hash(InnerCH1) + HRR + InnerCH2 + modified ServerHello.
        let mut modified_sh = server_hello_msg.to_vec();
        // ServerHello body starts at offset 4 (handshake header).
        // In the body: version(2) + random(32).
        // random starts at body offset 2, which is msg offset 6.
        // We need to zero bytes [24..32] of the random, i.e. msg[6+24..6+32] = msg[30..38].
        if modified_sh.len() >= 38 {
            modified_sh[30..38].fill(0);
        }

        let mut trial_transcript = TranscriptHash::new(hkdf_algo);
        trial_transcript.update(inner_hello);
        if self.hrr_received {
            trial_transcript.replace_with_message_hash();
            let hrr = self.hrr_raw_bytes.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailure("missing HRR transcript bytes for ECH".to_string())
            })?;
            let inner_ch2 = self.hrr_inner_ch2.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailure("missing inner CH2 transcript bytes for ECH".to_string())
            })?;
            trial_transcript.update(hrr);
            trial_transcript.update(inner_ch2);
        }
        trial_transcript.update(&modified_sh);
        let transcript_hash = trial_transcript.current_hash();

        // Per RFC 9849 §7.2, the confirmation secret is
        //   HKDF-Extract(salt=0, IKM=ClientHelloInner.random)
        // — NOT the handshake secret, and independent of the ECDH shared secret
        // and any PSK. ClientHelloInner.random is bytes [6..38] of the inner
        // handshake message (type(1) + length(3) + legacy_version(2) + random(32)).
        if inner_hello.len() < 38 {
            return Ok(false);
        }
        let inner_random = &inner_hello[6..38];
        let zero_salt = vec![0u8; hash_len];
        let ech_secret = hkdf_extract(hkdf_algo, &zero_salt, inner_random)?;

        // Output is exactly 8 bytes via HKDF-Expand-Label (length 8 encoded in
        // the label), not derive_secret()[..8].
        let accept_conf =
            ech_secret.expand_label("ech accept confirmation", &transcript_hash, 8)?;

        // Compare first 8 bytes with ServerHello.random[24..32].
        let expected = &server_random[24..32];
        let computed = &accept_conf[..8];

        if expected == computed {
            tracing::debug!("ECH accept confirmation matched");
            Ok(true)
        } else {
            tracing::debug!(
                "ECH accept confirmation mismatch: expected {:02x?}, computed {:02x?}",
                expected,
                computed,
            );
            Ok(false)
        }
    }

    fn check_ech_hrr_acceptance(
        &self,
        hkdf_algo: HkdfAlgorithm,
        inner_hello: &[u8],
        hrr_msg: &[u8],
        expected: &[u8; 8],
    ) -> Result<bool> {
        if inner_hello.len() < 38 {
            return Ok(false);
        }

        let mut modified_hrr = hrr_msg.to_vec();
        Self::zero_hrr_ech_confirmation(&mut modified_hrr)?;
        let mut transcript = TranscriptHash::new(hkdf_algo);
        transcript.update(inner_hello);
        transcript.replace_with_message_hash();
        transcript.update(&modified_hrr);

        let zero_salt = vec![0u8; hkdf_algo.hash_len()];
        let ech_secret = hkdf_extract(hkdf_algo, &zero_salt, &inner_hello[6..38])?;
        let confirmation = ech_secret.expand_label(
            "hrr ech accept confirmation",
            &transcript.current_hash(),
            8,
        )?;
        Ok(expected.as_slice() == confirmation.as_slice())
    }

    fn zero_hrr_ech_confirmation(hrr_msg: &mut [u8]) -> Result<()> {
        if hrr_msg.len() < 4 + 2 + 32 + 1 + 2 + 1 + 2 {
            return Err(TlsError::HandshakeFailure(
                "HRR too short for ECH confirmation".to_string(),
            ));
        }

        let mut pos = 4 + 2 + 32;
        let sid_len = hrr_msg[pos] as usize;
        pos += 1 + sid_len;
        if pos + 5 > hrr_msg.len() {
            return Err(TlsError::HandshakeFailure(
                "malformed HRR before extensions".to_string(),
            ));
        }
        pos += 2 + 1;
        let ext_len = u16::from_be_bytes([hrr_msg[pos], hrr_msg[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos
            .checked_add(ext_len)
            .filter(|end| *end <= hrr_msg.len())
            .ok_or_else(|| {
                TlsError::HandshakeFailure("malformed HRR extensions length".to_string())
            })?;

        while pos + 4 <= ext_end {
            let extension_type = u16::from_be_bytes([hrr_msg[pos], hrr_msg[pos + 1]]);
            let extension_len = u16::from_be_bytes([hrr_msg[pos + 2], hrr_msg[pos + 3]]) as usize;
            pos += 4;
            if pos + extension_len > ext_end {
                break;
            }
            if extension_type == ext_type::ENCRYPTED_CLIENT_HELLO && extension_len == 8 {
                hrr_msg[pos..pos + 8].fill(0);
                return Ok(());
            }
            pos += extension_len;
        }

        Err(TlsError::HandshakeFailure(
            "HRR ECH confirmation extension not found".to_string(),
        ))
    }

    // =======================================================================
    // Key derivation helpers
    // =======================================================================

    /// Compute ECDH shared secret from our key pair and the server's public key.
    fn compute_shared_secret(&mut self, sh: &ServerHello) -> Result<Vec<u8>> {
        let (server_group, server_public_key) =
            sh.extensions.key_share.as_ref().ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::MissingExtension,
                    "ServerHello missing key_share extension",
                )
            })?;
        tracing::debug!(
            "Server selected key_share group=0x{:04x}, server_pub_len={}",
            server_group,
            server_public_key.len()
        );

        // Find our key pair matching the server's group
        let kp_idx = self
            .key_pairs
            .iter()
            .position(|kp| kp.group.code_point() == *server_group)
            .ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "server selected group 0x{server_group:04x} but we don't have a key for it"
                    ),
                )
            })?;

        // Take ownership of the key pair (consumed by ECDH)
        let kp = self.key_pairs.swap_remove(kp_idx);
        let group = kp.group;
        kx::compute_shared_secret(kp, server_public_key).map_err(|error| {
            // Preserve the crypto rejection; only map the captured X25519/hybrid
            // failure behavior of these browser stacks to a wire alert.
            let alert = if matches!(group, KxGroup::X25519 | KxGroup::X25519MlKem768)
                && matches!(&error, TlsError::CryptoError(_))
            {
                match self.profile.tls_client_hello_style {
                    crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl => {
                        Some(AlertDescription::InternalError)
                    }
                    crate::profile::types::TlsClientHelloStyle::FirefoxNss => {
                        Some(AlertDescription::IllegalParameter)
                    }
                    _ => None,
                }
            } else {
                None
            };
            match alert {
                Some(alert) => TlsError::local_alert(alert, error.to_string()),
                None => error,
            }
        })
    }

    /// Derive handshake traffic keys from the shared secret.
    ///
    /// Follows TLS 1.3 key schedule (RFC 8446 Section 7.1):
    /// 1. Early Secret = HKDF-Extract(0, PSK) — PSK=0 for non-PSK, or the resumption PSK
    /// 2. Handshake Secret = Derive-Next(Early Secret, shared_secret)
    /// 3. client/server_handshake_traffic_secret = Derive-Secret(HS, label, CH..SH)
    /// 4. Derive key + IV from each traffic secret
    fn derive_handshake_keys(
        &mut self,
        hkdf_algo: HkdfAlgorithm,
        aead_algo: AeadAlgorithm,
        shared_secret: &[u8],
    ) -> Result<HandshakeKeys> {
        let hash_len = hkdf_algo.hash_len();

        // Step 1: Early Secret
        // If PSK was accepted and we cached the early secret, use it.
        // Otherwise, compute with zero IKM (non-PSK mode).
        let early_secret = if self.psk_accepted {
            if let Some(es) = self.early_secret_from_psk.take() {
                tracing::debug!("tls13.using_psk_early_secret");
                es
            } else {
                // Fallback: shouldn't happen, but compute from PSK if available
                let zero_salt = vec![0u8; hash_len];
                let zero_ikm = vec![0u8; hash_len];
                hkdf_extract(hkdf_algo, &zero_salt, &zero_ikm)?
            }
        } else {
            let zero_salt = vec![0u8; hash_len];
            let zero_ikm = vec![0u8; hash_len];
            hkdf_extract(hkdf_algo, &zero_salt, &zero_ikm)?
        };

        // Step 2: Handshake Secret = Derive-Next(Early Secret, shared_secret)
        let handshake_secret = early_secret.derive_next(shared_secret)?;

        // Step 3: Derive handshake traffic secrets
        let transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        let client_hs_secret = handshake_secret.derive_secret("c hs traffic", &transcript_hash)?;
        let server_hs_secret = handshake_secret.derive_secret("s hs traffic", &transcript_hash)?;

        // Step 4: Derive key + IV
        let client_key = hkdf_expand_label(
            hkdf_algo,
            &client_hs_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let client_iv = hkdf_expand_label(
            hkdf_algo,
            &client_hs_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;
        let server_key = hkdf_expand_label(
            hkdf_algo,
            &server_hs_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let server_iv = hkdf_expand_label(
            hkdf_algo,
            &server_hs_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;

        // Emit handshake traffic secrets via keylog callback (zero-cost when None)
        if let Some(ref cb) = self.keylog_callback {
            if let Some(cr) = self.client_random {
                let cr_hex = to_hex(&cr);
                cb(&format!(
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET {cr_hex} {}",
                    to_hex(&client_hs_secret)
                ));
                cb(&format!(
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET {cr_hex} {}",
                    to_hex(&server_hs_secret)
                ));
            }
        }

        // Save for later use
        self.handshake_secret = Some(handshake_secret);
        self.client_hs_traffic_secret = Some(client_hs_secret);
        self.server_hs_traffic_secret = Some(server_hs_secret);

        Ok(HandshakeKeys {
            hkdf_algorithm: hkdf_algo,
            aead_algorithm: aead_algo,
            server_secret: self.server_hs_traffic_secret.clone().unwrap_or_default(),
            client_secret: self.client_hs_traffic_secret.clone().unwrap_or_default(),
            server_key,
            server_iv,
            client_key,
            client_iv,
        })
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Compute the `verify_data` for a TLS 1.3 Finished message.
///
/// ```text
/// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
/// verify_data  = HMAC-Hash(finished_key, transcript_hash)
/// ```
fn compute_finished_verify_data(
    hkdf_algo: HkdfAlgorithm,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = hkdf_algo.hash_len();
    let finished_key = hkdf_expand_label(hkdf_algo, base_key, "finished", &[], hash_len)?;

    let hmac_algo = match hkdf_algo {
        HkdfAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HkdfAlgorithm::Sha384 => hmac::HMAC_SHA384,
    };

    let key = hmac::Key::new(hmac_algo, &finished_key);
    let tag = hmac::sign(&key, transcript_hash);
    Ok(tag.as_ref().to_vec())
}

/// Decompress a compressed certificate using the specified algorithm.
///
/// Supported algorithms (RFC 8879):
/// - 1: zlib
/// - 2: brotli
///
/// Maximum allowed decompressed certificate size (256 KB).
/// Real-world certificate chains rarely exceed 20 KB; 256 KB is generous.
const MAX_DECOMPRESSED_CERT_LEN: usize = 256 * 1024;

fn decompress_certificate(
    algorithm: u16,
    compressed: &[u8],
    max_uncompressed_len: usize,
) -> Result<Vec<u8>> {
    if max_uncompressed_len > MAX_DECOMPRESSED_CERT_LEN {
        return Err(TlsError::HandshakeFailure(format!(
            "decompressed certificate too large: {} bytes (max {})",
            max_uncompressed_len, MAX_DECOMPRESSED_CERT_LEN,
        )));
    }

    match algorithm {
        1 => {
            use flate2::read::ZlibDecoder;
            let mut decompressed = Vec::with_capacity(max_uncompressed_len);
            let mut reader = ZlibDecoder::new(compressed);
            std::io::Read::read_to_end(&mut reader, &mut decompressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("zlib decompression failed: {e}"))
            })?;
            if decompressed.len() != max_uncompressed_len {
                return Err(TlsError::HandshakeFailure(format!(
                    "decompressed certificate size mismatch: expected {}, got {}",
                    max_uncompressed_len,
                    decompressed.len()
                )));
            }
            Ok(decompressed)
        }
        2 => {
            let mut decompressed = Vec::with_capacity(max_uncompressed_len);
            let mut reader = brotli::Decompressor::new(compressed, 4096);
            std::io::Read::read_to_end(&mut reader, &mut decompressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("brotli decompression failed: {e}"))
            })?;
            if decompressed.len() != max_uncompressed_len {
                return Err(TlsError::HandshakeFailure(format!(
                    "decompressed certificate size mismatch: expected {}, got {}",
                    max_uncompressed_len,
                    decompressed.len()
                )));
            }
            Ok(decompressed)
        }
        3 => {
            // Zstandard (RFC 8879 §7.3). Advertised by the Firefox profiles,
            // which list `compress_cert_algorithms: [1, 2, 3]`; without this arm
            // a server that picked zstd failed the handshake outright.
            let mut decompressed = Vec::with_capacity(max_uncompressed_len);
            let mut reader = zstd::Decoder::new(compressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("zstd decoder init failed: {e}"))
            })?;
            std::io::Read::read_to_end(&mut reader, &mut decompressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("zstd decompression failed: {e}"))
            })?;
            if decompressed.len() != max_uncompressed_len {
                return Err(TlsError::HandshakeFailure(format!(
                    "decompressed certificate size mismatch: expected {}, got {}",
                    max_uncompressed_len,
                    decompressed.len()
                )));
            }
            Ok(decompressed)
        }
        _ => Err(TlsError::HandshakeFailure(format!(
            "unsupported certificate compression algorithm: {algorithm}"
        ))),
    }
}

/// Extract the request context from a TLS 1.3 CertificateRequest message.
fn parse_certificate_request_context(payload: &[u8]) -> Result<Vec<u8>> {
    let context_len = payload.first().copied().ok_or_else(|| {
        TlsError::UnexpectedMessage("truncated TLS 1.3 CertificateRequest".to_string())
    })? as usize;
    let context_end = 1usize.checked_add(context_len).ok_or_else(|| {
        TlsError::UnexpectedMessage("invalid TLS 1.3 CertificateRequest context".to_string())
    })?;
    if payload.len() < context_end {
        return Err(TlsError::UnexpectedMessage(
            "truncated TLS 1.3 CertificateRequest context".to_string(),
        ));
    }
    Ok(payload[1..context_end].to_vec())
}

fn build_empty_client_certificate(request_context: &[u8]) -> Vec<u8> {
    let body_len = 1 + request_context.len() + 3;
    let mut message = Vec::with_capacity(4 + body_len);
    message.push(handshake_type::CERTIFICATE);
    message.push(((body_len as u32) >> 16) as u8);
    message.push(((body_len as u32) >> 8) as u8);
    message.push(body_len as u8);
    message.push(request_context.len() as u8);
    message.extend_from_slice(request_context);
    message.extend_from_slice(&[0, 0, 0]);
    message
}

/// Parse a TLS 1.3 Certificate handshake message.
///
/// Returns a list of DER-encoded certificates (leaf first).
fn parse_certificate_message(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut pos = 0;

    // certificate_request_context<0..255>
    // RFC 8446 §4.4.2: for server auth this field SHALL be zero length
    if pos >= payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate message too short".to_string(),
        ));
    }
    let ctx_len = payload[pos] as usize;
    if ctx_len != 0 {
        return Err(TlsError::HandshakeFailure(format!(
            "server Certificate has non-empty request_context (len={})",
            ctx_len,
        )));
    }
    pos += 1 + ctx_len;

    // certificate_list<0..2^24-1>
    if pos + 3 > payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate message truncated at list length".to_string(),
        ));
    }
    let list_len = ((payload[pos] as usize) << 16)
        | ((payload[pos + 1] as usize) << 8)
        | (payload[pos + 2] as usize);
    pos += 3;

    let list_end = pos + list_len;
    if list_end > payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate list length exceeds message".to_string(),
        ));
    }

    let mut certs = Vec::new();
    while pos + 3 <= list_end {
        // cert_data<1..2^24-1>
        let cert_len = ((payload[pos] as usize) << 16)
            | ((payload[pos + 1] as usize) << 8)
            | (payload[pos + 2] as usize);
        pos += 3;

        if pos + cert_len > list_end {
            return Err(TlsError::UnexpectedMessage(
                "Certificate entry exceeds list".to_string(),
            ));
        }
        certs.push(payload[pos..pos + cert_len].to_vec());
        pos += cert_len;

        // extensions<0..2^16-1> (per-certificate extensions)
        if pos + 2 > list_end {
            break;
        }
        let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }

    Ok(certs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_client_certificate_echoes_request_context() {
        assert_eq!(parse_certificate_request_context(&[0, 0, 0]).unwrap(), b"");
        assert_eq!(
            parse_certificate_request_context(&[3, 0xAA, 0xBB, 0xCC, 0, 0]).unwrap(),
            [0xAA, 0xBB, 0xCC]
        );
        assert!(parse_certificate_request_context(&[2, 0xAA]).is_err());

        assert_eq!(
            build_empty_client_certificate(&[]),
            [handshake_type::CERTIFICATE, 0, 0, 4, 0, 0, 0, 0]
        );
        assert_eq!(
            build_empty_client_certificate(&[0xAA, 0xBB]),
            [handshake_type::CERTIFICATE, 0, 0, 6, 2, 0xAA, 0xBB, 0, 0, 0,]
        );
    }

    fn build_hrr(session_id: &[u8], cipher_suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![handshake_type::SERVER_HELLO];
        let body_len = body.len() as u32;
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn chromium_fixed_serverhello_fields_fail_before_keys_or_retry_on_tcp_and_quic() {
        for quic in [false, true] {
            for retry in [false, true] {
                for field in 0..3 {
                    let mut handshake =
                        Tls13Handshake::new(crate::profile::presets::chrome_155(), "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    handshake.build_client_hello().unwrap();
                    let mut session_id = handshake.session_id.clone().unwrap();
                    if field == 2 {
                        if session_id.is_empty() {
                            session_id.push(0xa5);
                        } else {
                            session_id[0] ^= 1;
                        }
                    }
                    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                    let share = if retry {
                        vec![0, 24]
                    } else {
                        let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
                        let mut share = vec![0, 29];
                        share.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                        share.extend_from_slice(&key.public_key);
                        share
                    };
                    extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
                    extensions.extend_from_slice(&share);
                    let mut message = build_hrr(&session_id, 0x1301, &extensions);
                    if !retry {
                        message[6..38].fill(0x55);
                    }
                    if field == 0 {
                        message[5] = 2;
                    } else if field == 1 {
                        message[41 + session_id.len()] = 1;
                    }
                    let result = handshake.process_handshake_record(&message);
                    assert!(
                        matches!(&result,
                            Err(TlsError::LocalAlert { alert, .. })
                            if alert.description == AlertDescription::DecodeError),
                        "quic={quic} retry={retry} field={field} keys={} ch2={} error={:?}",
                        matches!(&result, Ok(HandshakeAction::InstallHandshakeKeys(_))),
                        matches!(&result, Ok(HandshakeAction::RetryClientHello(_))),
                        result.as_ref().err(),
                    );
                    assert_eq!(handshake.state, Tls13State::WaitServerHello);
                    assert!(!handshake.hrr_received);
                    assert!(handshake.client_hs_traffic_secret.is_none());
                    assert!(handshake.server_hs_traffic_secret.is_none());
                }
            }
        }
    }

    #[test]
    fn firefox_nss_retry_uses_supported_version_not_legacy_version() {
        let mut handshake =
            Tls13Handshake::new(crate::profile::presets::firefox_156(), "localhost");
        handshake.build_client_hello().unwrap();
        let mut message = build_hrr(
            handshake.session_id.as_ref().unwrap(),
            0x1301,
            &[0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 24],
        );
        message[5] = 2;
        let result = handshake.process_handshake_record(&message);
        assert!(
            matches!(&result, Ok(HandshakeAction::RetryClientHello(_))),
            "NSS must answer this HRR: {:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn firefox_nss_fixed_fields_follow_stack_alerts_on_tcp_and_quic() {
        for quic in [false, true] {
            for retry in [false, true] {
                for field in 0..7 {
                    let mut handshake =
                        Tls13Handshake::new(crate::profile::presets::firefox_156(), "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    handshake.build_client_hello().unwrap();
                    let mut session_id = handshake.session_id.clone().unwrap();
                    if field == 3 {
                        if session_id.is_empty() {
                            session_id.push(0xa5);
                        } else {
                            session_id[0] ^= 1;
                        }
                    }
                    let share = if retry {
                        vec![0, 24]
                    } else {
                        let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
                        let mut share = vec![0, 29];
                        share.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                        share.extend_from_slice(&key.public_key);
                        share
                    };
                    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                    extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
                    extensions.extend_from_slice(&share);
                    let mut message = build_hrr(&session_id, 0x1301, &extensions);
                    if !retry {
                        message[6..38].fill(0x55);
                    }
                    message[5] = match field {
                        0 => 0,
                        1 => 4,
                        4 => 1,
                        5 => 2,
                        _ => 3,
                    };
                    if field == 2 {
                        message[41 + session_id.len()] = 1;
                    }
                    let result = handshake.process_handshake_record(&message);
                    if field < 4 {
                        let expected = if field == 0 {
                            AlertDescription::ProtocolVersion
                        } else {
                            AlertDescription::IllegalParameter
                        };
                        assert!(
                            matches!(&result, Err(TlsError::LocalAlert { alert, .. })
                            if alert.description == expected),
                            "quic={quic} retry={retry} field={field} keys={} error={:?}",
                            matches!(&result, Ok(HandshakeAction::InstallHandshakeKeys(_))),
                            result.as_ref().err()
                        );
                        assert!(!handshake.hrr_received);
                        assert!(handshake.client_hs_traffic_secret.is_none());
                        assert!(handshake.server_hs_traffic_secret.is_none());
                    } else if retry {
                        assert!(matches!(result, Ok(HandshakeAction::RetryClientHello(_))));
                    } else {
                        assert!(matches!(
                            result,
                            Ok(HandshakeAction::InstallHandshakeKeys(_))
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn firefox_nss_legacy_version_is_ignored_when_supported_versions_selects_tls13() {
        let mut handshake =
            Tls13Handshake::new(crate::profile::presets::firefox_156(), "localhost");
        handshake.build_client_hello().unwrap();
        let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
        extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&[0, 29]);
        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key.public_key);
        let mut message = build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
        message[5] = 2;
        message[6..38].fill(0x55);
        assert!(matches!(
            handshake.process_handshake_record(&message),
            Ok(HandshakeAction::InstallHandshakeKeys(_))
        ));
    }

    fn test_psk_ticket(sha384: bool) -> SessionTicketData {
        SessionTicketData {
            ticket: b"local-payload-test".to_vec(),
            resumption_psk: vec![0xa5; if sha384 { 48 } else { 32 }],
            tls_version: crate::session_store::TicketTlsVersion::Tls13,
            cipher_suite: if sha384 { 0x1302 } else { 0x1301 },
            lifetime_secs: 3600,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn: None,
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm: if sha384 {
                HkdfAlgorithm::Sha384
            } else {
                HkdfAlgorithm::Sha256
            },
            aead_algorithm: if sha384 {
                AeadAlgorithm::Aes256Gcm
            } else {
                AeadAlgorithm::Aes128Gcm
            },
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        }
    }

    fn serverhello_cipher_alert_matrix(cases: &[usize]) -> Vec<Vec<Option<AlertDescription>>> {
        let mut rows = Vec::new();
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for quic in [false, true] {
                let mut row = Vec::new();
                for &case in cases {
                    let mut configured = profile.clone();
                    if case == 0 {
                        configured.cipher_suites.retain(|suite| *suite != 0x1301);
                    }
                    let mut handshake = Tls13Handshake::new(configured, "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    let ch1 = handshake.build_client_hello().unwrap();
                    let cipher = match case {
                        1 => 0xc02f,
                        2 => 0xffff,
                        3 => 0x1303,
                        4 => 0x1302,
                        6 | 9 => 0x1302,
                        7 | 10 => 0x1303,
                        _ => 0x1301,
                    };
                    let retry = matches!(case, 3 | 4 | 8 | 9 | 10);
                    let offered = client_hello_legacy_offer(&ch1).unwrap().0;
                    if case < 3 {
                        assert_eq!(offered.contains(&cipher), case == 1);
                    }
                    if retry {
                        let first_cipher = if case < 5 { 0x1301 } else { cipher };
                        let hrr = build_hrr(
                            handshake.session_id.as_ref().unwrap(),
                            first_cipher,
                            &[0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 24],
                        );
                        assert!(matches!(
                            handshake.process_handshake_record(&hrr).unwrap(),
                            HandshakeAction::RetryClientHello(_)
                        ));
                    }
                    let group = if retry {
                        KxGroup::Secp384r1
                    } else {
                        KxGroup::X25519
                    };
                    let key = kx::generate_key_pair(group).unwrap();
                    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                    extensions
                        .extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
                    extensions.extend_from_slice(&group.code_point().to_be_bytes());
                    extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                    extensions.extend_from_slice(&key.public_key);
                    let mut sh =
                        build_hrr(handshake.session_id.as_ref().unwrap(), cipher, &extensions);
                    sh[6..38].fill(0x55);
                    match handshake.process_handshake_record(&sh) {
                        Ok(HandshakeAction::InstallHandshakeKeys(_)) => {
                            assert!(case >= 5, "invalid cipher choice installed keys");
                            row.push(None);
                        }
                        Err(TlsError::LocalAlert { alert, .. }) => {
                            assert!(handshake.client_hs_traffic_secret.is_none());
                            assert!(handshake.server_hs_traffic_secret.is_none());
                            row.push(Some(alert.description));
                        }
                        Err(error) => panic!("case={case} quic={quic}: {error:?}"),
                        _ => panic!("unexpected handshake action"),
                    }
                }
                rows.push(row);
            }
        }
        rows
    }

    #[test]
    fn missing_and_unoffered_key_share_errors_match_captured_browser_alerts() {
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for quic in [false, true] {
                for missing in [true, false] {
                    let mut handshake = Tls13Handshake::new(profile.clone(), "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    handshake.build_client_hello().unwrap();
                    assert!(!handshake
                        .key_pairs
                        .iter()
                        .any(|pair| pair.group == KxGroup::Secp384r1));
                    let mut extensions = vec![0, 43, 0, 2, 3, 4];
                    if !missing {
                        let key = kx::generate_key_pair(KxGroup::Secp384r1).unwrap();
                        extensions.extend_from_slice(&[0, 51]);
                        extensions
                            .extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
                        extensions.extend_from_slice(&[0, 24]);
                        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                        extensions.extend_from_slice(&key.public_key);
                    }
                    let mut sh =
                        build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
                    sh[6..38].fill(0x55);
                    let expected = if missing {
                        AlertDescription::MissingExtension
                    } else {
                        AlertDescription::IllegalParameter
                    };
                    assert!(
                        matches!(handshake.process_handshake_record(&sh), Err(TlsError::LocalAlert { alert, .. })
                        if alert.description == expected)
                    );
                    assert!(handshake.client_hs_traffic_secret.is_none());
                    assert!(handshake.server_hs_traffic_secret.is_none());
                }
            }
        }
    }

    #[test]
    fn serverhello_cipher_selection_emits_illegal_parameter() {
        let expected = vec![Some(AlertDescription::IllegalParameter); 3]
            .into_iter()
            .chain([None; 3])
            .collect::<Vec<_>>();
        assert_eq!(
            serverhello_cipher_alert_matrix(&[0, 1, 2, 5, 6, 7]),
            [
                expected.clone(),
                expected.clone(),
                expected.clone(),
                expected
            ]
        );
    }

    #[test]
    fn hrr_cipher_changes_emit_illegal_parameter_and_retained_ciphers_work() {
        let expected = vec![Some(AlertDescription::IllegalParameter); 2]
            .into_iter()
            .chain([None; 3])
            .collect::<Vec<_>>();
        assert_eq!(
            serverhello_cipher_alert_matrix(&[3, 4, 8, 9, 10]),
            [
                expected.clone(),
                expected.clone(),
                expected.clone(),
                expected
            ]
        );
    }

    #[test]
    fn hrr_psk_offer_tracks_selected_hash_and_latest_client_hello() {
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for quic in [false, true] {
                for ticket_sha384 in [false, true] {
                    for hrr_sha384 in [true, false] {
                        for select_psk in [false, true] {
                            let mut handshake = Tls13Handshake::new(profile.clone(), "localhost");
                            if quic {
                                handshake.enable_quic_mode();
                                handshake.set_quic_transport_parameters(Vec::new());
                            }
                            handshake.set_psk_ticket(test_psk_ticket(ticket_sha384));
                            let ch1 = handshake.build_client_hello().unwrap();
                            assert!(client_hello_extension(&ch1, 41).is_some());
                            let cipher = if hrr_sha384 { 0x1302 } else { 0x1301 };
                            let hrr = build_hrr(
                                handshake.session_id.as_ref().unwrap(),
                                cipher,
                                &[0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 24],
                            );
                            let HandshakeAction::RetryClientHello(ch2) =
                                handshake.process_handshake_record(&hrr).unwrap()
                            else {
                                panic!("HRR must emit CH2");
                            };
                            let compatible = ticket_sha384 == hrr_sha384;
                            assert_eq!(
                                client_hello_extension(&ch2, 41).is_some(),
                                compatible,
                                "CH2 must omit PSKs with a different hash"
                            );
                            assert_eq!(
                                handshake.offered_extensions.as_ref().unwrap().contains(&41),
                                compatible
                            );
                            let key = kx::generate_key_pair(KxGroup::Secp384r1).unwrap();
                            let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                            extensions.extend_from_slice(
                                &((4 + key.public_key.len()) as u16).to_be_bytes(),
                            );
                            extensions.extend_from_slice(&[0, 24]);
                            extensions
                                .extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                            extensions.extend_from_slice(&key.public_key);
                            if select_psk {
                                extensions.extend_from_slice(&[0, 41, 0, 2, 0, 0]);
                            }
                            let mut sh = build_hrr(
                                handshake.session_id.as_ref().unwrap(),
                                cipher,
                                &extensions,
                            );
                            sh[6..38].fill(0x55);
                            let result = handshake.process_handshake_record(&sh);
                            if select_psk && !compatible {
                                assert!(matches!(result, Err(TlsError::LocalAlert { alert, .. })
                                    if alert.description == AlertDescription::UnsupportedExtension));
                                assert!(handshake.client_hs_traffic_secret.is_none());
                            } else {
                                assert!(matches!(
                                    result,
                                    Ok(HandshakeAction::InstallHandshakeKeys(_))
                                ));
                                assert_eq!(handshake.psk_accepted, select_psk);
                            }
                        }
                    }
                }
            }
        }
    }

    fn serverhello_payload_alert_matrix(
        kind: u16,
        cases: &[usize],
    ) -> Vec<Vec<Option<AlertDescription>>> {
        let mut rows = Vec::new();
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for quic in [false, true] {
                let mut row = Vec::new();
                for &case in cases {
                    let mut handshake = Tls13Handshake::new(profile.clone(), "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    if kind == 41 && case != 4 {
                        let sha384 = matches!(case, 7 | 8);
                        handshake.set_psk_ticket(test_psk_ticket(sha384));
                    }
                    handshake.build_client_hello().unwrap();
                    let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
                    let mut share = vec![0, 29];
                    share.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                    share.extend_from_slice(&key.public_key);
                    if kind == 51 {
                        match case {
                            0 => share.push(0xa5),
                            1 => share.truncate(3),
                            2 => {
                                share.truncate(4);
                                share[3] = 1;
                            }
                            4 | 6 => {
                                share[4..].fill(0);
                                if case == 6 {
                                    share[4] = 1;
                                }
                            }
                            5 => {
                                share[4..].fill(0);
                                share.truncate(35);
                                share[3] = 31;
                            }
                            _ => {}
                        }
                    }
                    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                    extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
                    extensions.extend_from_slice(&share);
                    if kind == 41 {
                        let identity: &[u8] = match case {
                            0 | 4 => &[0, 0, 0xa5],
                            1 => &[],
                            2 => &[0],
                            5 => &[0, 1],
                            _ => &[0, 0],
                        };
                        extensions.extend_from_slice(&[0, 41]);
                        extensions.extend_from_slice(&(identity.len() as u16).to_be_bytes());
                        extensions.extend_from_slice(identity);
                    }
                    let cipher = if kind == 41 && matches!(case, 6 | 7) {
                        0x1302
                    } else {
                        0x1301
                    };
                    let mut message =
                        build_hrr(handshake.session_id.as_ref().unwrap(), cipher, &extensions);
                    message[6..38].fill(0x55);
                    match handshake.process_handshake_record(&message) {
                        Ok(HandshakeAction::InstallHandshakeKeys(_)) => {
                            assert!(
                                matches!(case, 3 | 7),
                                "malformed kind={kind} quic={quic} installed handshake keys"
                            );
                            assert_eq!(handshake.psk_accepted, kind == 41);
                            row.push(None);
                        }
                        Err(TlsError::LocalAlert { alert, .. }) => {
                            assert!(!handshake.psk_accepted);
                            assert!(handshake.client_hs_traffic_secret.is_none());
                            assert!(handshake.server_hs_traffic_secret.is_none());
                            row.push(Some(alert.description));
                        }
                        Err(error) => panic!("kind={kind} case={case} quic={quic}: {error:?}"),
                        _ => panic!("unexpected handshake action"),
                    }
                }
                rows.push(row);
            }
        }
        rows
    }

    #[test]
    fn hybrid_key_values_use_browser_alerts_and_valid_encapsulation_works() {
        for (profile, nss) in [
            (crate::profile::presets::chrome_155(), false),
            (crate::profile::presets::firefox_156(), true),
        ] {
            for quic in [false, true] {
                for case in 0..4 {
                    let mut handshake = Tls13Handshake::new(profile.clone(), "localhost");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(Vec::new());
                    }
                    handshake.build_client_hello().unwrap();
                    let client = &handshake
                        .key_pairs
                        .iter()
                        .find(|key| key.group == KxGroup::X25519MlKem768)
                        .unwrap()
                        .public_key;
                    let kem = aws_lc_rs::kem::EncapsulationKey::new(
                        &aws_lc_rs::kem::ML_KEM_768,
                        &client[..1184],
                    )
                    .unwrap();
                    let (ciphertext, _) = kem.encapsulate().unwrap();
                    let server = kx::generate_key_pair(KxGroup::X25519).unwrap();
                    let mut public = if case == 3 {
                        let mut value = ciphertext.as_ref().to_vec();
                        value.extend_from_slice(&server.public_key);
                        value
                    } else {
                        vec![0; if case == 0 { 1119 } else { 1120 }]
                    };
                    if case == 2 {
                        public[1088] = 1;
                    }
                    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                    extensions.extend_from_slice(&((4 + public.len()) as u16).to_be_bytes());
                    extensions.extend_from_slice(&[0x11, 0xec]);
                    extensions.extend_from_slice(&(public.len() as u16).to_be_bytes());
                    extensions.extend_from_slice(&public);
                    let mut sh =
                        build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
                    sh[6..38].fill(0x55);
                    let result = handshake.process_handshake_record(&sh);
                    if case == 3 {
                        assert!(matches!(
                            result,
                            Ok(HandshakeAction::InstallHandshakeKeys(_))
                        ));
                    } else {
                        let expected = if nss {
                            AlertDescription::IllegalParameter
                        } else {
                            AlertDescription::InternalError
                        };
                        assert!(
                            matches!(&result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == expected),
                            "nss={nss} quic={quic} case={case}: {:?}",
                            result.as_ref().err()
                        );
                        assert!(handshake.client_hs_traffic_secret.is_none());
                        assert!(handshake.server_hs_traffic_secret.is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn invalid_x25519_values_use_captured_browser_alerts() {
        let chrome = vec![
            Some(AlertDescription::InternalError),
            Some(AlertDescription::InternalError),
            Some(AlertDescription::InternalError),
            None,
        ];
        let firefox = vec![
            Some(AlertDescription::IllegalParameter),
            Some(AlertDescription::IllegalParameter),
            Some(AlertDescription::IllegalParameter),
            None,
        ];
        assert_eq!(
            serverhello_payload_alert_matrix(51, &[4, 5, 6, 3]),
            [chrome.clone(), chrome, firefox.clone(), firefox]
        );
    }

    #[test]
    fn serverhello_key_share_payload_length_uses_browser_alerts() {
        use AlertDescription::{DecodeError, HandshakeFailure, IllegalParameter};
        let chromium = vec![
            Some(DecodeError),
            Some(DecodeError),
            Some(DecodeError),
            None,
        ];
        let nss = vec![
            Some(HandshakeFailure),
            Some(IllegalParameter),
            Some(IllegalParameter),
            None,
        ];
        assert_eq!(
            serverhello_payload_alert_matrix(51, &[0, 1, 2, 3]),
            [chromium.clone(), chromium, nss.clone(), nss]
        );
    }

    #[test]
    fn serverhello_psk_payload_length_preserves_unsolicited_extension_precedence() {
        use AlertDescription::{DecodeError, HandshakeFailure, UnsupportedExtension};
        let chromium = vec![
            Some(DecodeError),
            Some(DecodeError),
            Some(DecodeError),
            None,
            Some(UnsupportedExtension),
        ];
        let nss = vec![
            Some(HandshakeFailure),
            Some(DecodeError),
            Some(DecodeError),
            None,
            Some(UnsupportedExtension),
        ];
        assert_eq!(
            serverhello_payload_alert_matrix(41, &[0, 1, 2, 3, 4]),
            [chromium.clone(), chromium, nss.clone(), nss]
        );
    }

    #[test]
    fn serverhello_psk_index_uses_browser_alerts() {
        use AlertDescription::{IllegalParameter, UnknownPskIdentity};
        assert_eq!(
            serverhello_payload_alert_matrix(41, &[5]),
            [
                vec![Some(UnknownPskIdentity)],
                vec![Some(UnknownPskIdentity)],
                vec![Some(IllegalParameter)],
                vec![Some(IllegalParameter)],
            ]
        );
    }

    #[test]
    fn serverhello_psk_hash_mismatch_and_sha384_resumption() {
        use AlertDescription::IllegalParameter;
        let expected = vec![Some(IllegalParameter), Some(IllegalParameter), None];
        assert_eq!(
            serverhello_payload_alert_matrix(41, &[6, 8, 7]),
            [
                expected.clone(),
                expected.clone(),
                expected.clone(),
                expected,
            ]
        );
    }

    fn client_hello_extension(message: &[u8], target: u16) -> Option<Vec<u8>> {
        let body = message.get(4..)?;
        let sid_len = *body.get(34)? as usize;
        let mut pos = 35 + sid_len;
        let cipher_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
        pos += 2 + cipher_len;
        let compression_len = *body.get(pos)? as usize;
        pos += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
        pos += 2;
        let extensions_end = pos.checked_add(extensions_len)?;
        while pos + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            let extension_end = pos.checked_add(extension_len)?;
            if extension_end > extensions_end {
                return None;
            }
            if extension_type == target {
                return Some(body[pos..extension_end].to_vec());
            }
            pos = extension_end;
        }
        None
    }

    fn client_hello_extension_types(message: &[u8]) -> Vec<u16> {
        let Some(body) = message.get(4..) else {
            return Vec::new();
        };
        let Some(&sid_len) = body.get(34) else {
            return Vec::new();
        };
        let mut pos = 35 + sid_len as usize;
        let Some(cipher_len_bytes) = body.get(pos..pos + 2) else {
            return Vec::new();
        };
        let cipher_len = u16::from_be_bytes([cipher_len_bytes[0], cipher_len_bytes[1]]) as usize;
        pos += 2 + cipher_len;
        let Some(&compression_len) = body.get(pos) else {
            return Vec::new();
        };
        pos += 1 + compression_len as usize;
        let Some(extensions_len_bytes) = body.get(pos..pos + 2) else {
            return Vec::new();
        };
        let extensions_len =
            u16::from_be_bytes([extensions_len_bytes[0], extensions_len_bytes[1]]) as usize;
        pos += 2;
        let extensions_end = pos.saturating_add(extensions_len).min(body.len());
        let mut types = Vec::new();
        while pos + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            let extension_end = pos.saturating_add(extension_len);
            if extension_end > extensions_end {
                return Vec::new();
            }
            types.push(extension_type);
            pos = extension_end;
        }
        types
    }

    fn psk_binder(extension_data: &[u8]) -> Vec<u8> {
        let identities_len = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
        let binders_len_pos = 2 + identities_len;
        let binder_len_pos = binders_len_pos + 2;
        let binder_len = extension_data[binder_len_pos] as usize;
        extension_data[binder_len_pos + 1..binder_len_pos + 1 + binder_len].to_vec()
    }

    fn build_test_ech_config_list() -> Vec<u8> {
        use hpke::kem::X25519HkdfSha256;
        use hpke::{Kem, Serializable};
        use rand_core::TryRngCore;

        let (_secret_key, public_key) =
            X25519HkdfSha256::gen_keypair(&mut rand_core::OsRng.unwrap_err());
        let public_key = public_key.to_bytes();
        let mut contents = Vec::new();
        contents.push(42);
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.push(32);
        let public_name = b"public.example.com";
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name);
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut config = Vec::new();
        config.extend_from_slice(&0xFE0Du16.to_be_bytes());
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);

        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        list
    }

    #[test]
    fn test_cipher_suite_info() {
        let (hkdf, aead) = cipher_suite_info(0x1301).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha256);
        assert_eq!(aead, AeadAlgorithm::Aes128Gcm);

        let (hkdf, aead) = cipher_suite_info(0x1302).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha384);
        assert_eq!(aead, AeadAlgorithm::Aes256Gcm);

        let (hkdf, aead) = cipher_suite_info(0x1303).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha256);
        assert_eq!(aead, AeadAlgorithm::Chacha20Poly1305);

        assert!(cipher_suite_info(0xFFFF).is_err());
    }

    #[test]
    fn test_transcript_hash_basic() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th.update(b"hello");
        let h1 = th.current_hash();
        assert_eq!(h1.len(), 32);

        // Updating should change the hash
        th.update(b"world");
        let h2 = th.current_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_transcript_hash_message_hash_replacement() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th.update(b"ClientHello1 data");
        let hash_before = th.current_hash();

        th.replace_with_message_hash();

        // After replacement, the hash should be different
        let hash_after = th.current_hash();
        assert_ne!(hash_before, hash_after);
        assert_eq!(hash_after.len(), 32);
    }

    #[test]
    fn test_zero_hrr_ech_confirmation() {
        let confirmation = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&server_hello::HRR_RANDOM);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&12u16.to_be_bytes());
        body.extend_from_slice(&ext_type::ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&confirmation);

        let mut hrr = vec![handshake_type::SERVER_HELLO, 0, 0, body.len() as u8];
        hrr.extend_from_slice(&body);
        Tls13Handshake::zero_hrr_ech_confirmation(&mut hrr).unwrap();
        assert!(hrr.ends_with(&[0u8; 8]));
    }

    #[test]
    fn test_cookie_only_hrr_preserves_key_share() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        let ch1 = handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();

        let cookie = b"retry-cookie";
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&ext_type::COOKIE.to_be_bytes());
        extensions.extend_from_slice(&((2 + cookie.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        extensions.extend_from_slice(cookie);

        let hrr = build_hrr(&session_id, cipher_suite, &extensions);
        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2) = action else {
            panic!("expected retry ClientHello");
        };

        assert_eq!(
            client_hello_extension(&ch2, ext_type::KEY_SHARE),
            client_hello_extension(&ch1, ext_type::KEY_SHARE),
        );
        assert_eq!(
            client_hello_extension(&ch2, ext_type::COOKIE),
            Some([&(cookie.len() as u16).to_be_bytes()[..], cookie].concat()),
        );
    }

    #[test]
    fn hrr_preserves_trust_anchor_order_on_tcp_and_quic() {
        for profile in [
            crate::profile::presets::chrome_152(),
            crate::profile::presets::chrome_153(),
            crate::profile::presets::chrome_154(),
            crate::profile::presets::chrome_155(),
        ] {
            for quic in [false, true] {
                for replace_key_share in [false, true] {
                    let cipher_suite = profile
                        .cipher_suites
                        .iter()
                        .copied()
                        .find(|value| *value == 0x1301)
                        .unwrap();
                    let mut handshake = Tls13Handshake::new(profile.clone(), "example.com");
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(vec![1, 1, 0]);
                    }
                    let ch1 = handshake.build_client_hello().unwrap();
                    let session_id = handshake.session_id.clone().unwrap();
                    let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
                    if replace_key_share {
                        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x18]);
                    } else {
                        extensions.extend_from_slice(&[0x00, 0x2c, 0x00, 0x03, 0x00, 0x01, 0xa5]);
                    }
                    let hrr = build_hrr(&session_id, cipher_suite, &extensions);
                    let HandshakeAction::RetryClientHello(ch2) =
                        handshake.process_handshake_record(&hrr).unwrap()
                    else {
                        panic!("expected retry ClientHello");
                    };
                    let original =
                        client_hello_extension(&ch1, 0xca34).expect("Chrome trust anchors");
                    assert_eq!(
                        client_hello_extension(&ch2, 0xca34).unwrap(),
                        original,
                        "trust anchor order changed: quic={quic}, key-share HRR={replace_key_share}",
                    );
                }
            }
        }
    }

    /// RFC 8446 §4.4.3: the server must sign CertificateVerify with an
    /// algorithm the client advertised. Completing on one we never offered is a
    /// protocol violation, and for a client whose purpose is to look like a
    /// specific browser it is a contradiction the server can see.
    #[test]
    fn certificate_verify_rejects_a_scheme_the_client_did_not_offer() {
        let profile = crate::profile::presets::chrome_150();
        // ed448 (0x0808) is not in any Chrome profile.
        let not_offered = 0x0808;
        assert!(
            !profile.signature_algorithms.contains(&not_offered),
            "test premise: chrome_150 must not advertise 0x{not_offered:04x}"
        );
        let handshake = Tls13Handshake::new(profile, "example.com");

        let err = handshake
            .check_certificate_verify_scheme(not_offered)
            .expect_err("an unoffered scheme must be rejected");
        assert!(
            err.to_string().contains("did not offer"),
            "unexpected error: {err}"
        );
    }

    /// A scheme we did advertise is accepted — the check must not reject
    /// everything.
    #[test]
    fn certificate_verify_accepts_an_offered_scheme() {
        let profile = crate::profile::presets::chrome_150();
        // ecdsa_secp256r1_sha256, offered by every Chrome profile and legal in
        // CertificateVerify.
        let offered = 0x0403;
        assert!(
            profile.signature_algorithms.contains(&offered),
            "test premise: chrome_150 must advertise 0x{offered:04x}"
        );
        let handshake = Tls13Handshake::new(profile, "example.com");

        assert!(
            handshake.check_certificate_verify_scheme(offered).is_ok(),
            "an offered, CertificateVerify-legal scheme must be accepted"
        );
    }

    /// RFC 8446 §4.4.3 bans `rsa_pkcs1_*` from CertificateVerify even though the
    /// profiles advertise those code points — they are legal for signatures *on
    /// certificates*, not for this message. Advertised must not imply accepted
    /// here.
    #[test]
    fn certificate_verify_rejects_rsa_pkcs1_even_though_it_is_advertised() {
        let profile = crate::profile::presets::chrome_150();
        for scheme in [0x0401u16, 0x0501, 0x0601] {
            assert!(
                profile.signature_algorithms.contains(&scheme),
                "test premise: chrome_150 advertises rsa_pkcs1 0x{scheme:04x} \
                 for certificate signatures"
            );
        }

        let handshake = Tls13Handshake::new(profile, "example.com");
        for scheme in [0x0201u16, 0x0401, 0x0501, 0x0601] {
            let err = handshake
                .check_certificate_verify_scheme(scheme)
                .expect_err("rsa_pkcs1 must be refused in CertificateVerify");
            assert!(
                err.to_string().contains("rsa_pkcs1"),
                "unexpected error for 0x{scheme:04x}: {err}"
            );
        }
    }

    /// RFC 8446 §4.2: a server must not answer with an extension the client
    /// never offered, and the client must abort when it does.
    #[test]
    fn encrypted_extensions_reject_an_extension_never_offered() {
        let profile = crate::profile::presets::chrome_150();
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();

        // 0x0015 (padding) is never sent by these profiles in a way the server
        // may echo, and is not an EncryptedExtensions response extension.
        let never_offered = 0x0015;
        assert!(
            handshake
                .offered_extensions
                .as_ref()
                .is_some_and(|offered| !offered.contains(&never_offered)),
            "test premise: the ClientHello must not have offered 0x{never_offered:04x}"
        );

        assert!(
            handshake
                .check_encrypted_extension_offered(never_offered)
                .is_err(),
            "an unsolicited EncryptedExtensions extension must be rejected"
        );
    }

    /// The same check must accept what we did offer, or every handshake breaks.
    #[test]
    fn encrypted_extensions_accept_an_offered_extension() {
        let profile = crate::profile::presets::chrome_150();
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();

        let offered = handshake
            .offered_extensions
            .as_ref()
            .and_then(|offered| offered.first().copied())
            .expect("the ClientHello offered at least one extension");

        assert!(
            handshake.check_encrypted_extension_offered(offered).is_ok(),
            "an extension we offered (0x{offered:04x}) must be accepted"
        );
    }

    #[test]
    fn encrypted_extensions_reject_unoffered_alpn_protocol() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.alpn_protocols = vec!["h2".into()];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let message = encrypted_extensions_message(&[(ext_type::ALPN, vec![0, 3, 2, b'h', b'3'])]);
        assert!(
            matches!(handshake.process_encrypted_extensions(&message, &message[4..]), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
        );
    }

    fn early_data_test_handshake(quic: bool) -> Tls13Handshake {
        early_data_test_handshake_with_profile(quic, crate::profile::presets::chrome_155_quic())
    }

    fn early_data_test_handshake_with_profile(
        quic: bool,
        mut profile: TlsProfile,
    ) -> Tls13Handshake {
        profile.alpn_protocols = vec!["h3".into(), "h2".into()];
        if !profile
            .extensions
            .iter()
            .any(|extension| extension.extension_type == ext_type::EARLY_DATA)
        {
            profile.extensions.push(ExtensionSpec {
                extension_type: ext_type::EARLY_DATA,
                source: ExtensionSource::Auto,
            });
        }
        if !quic {
            profile.extensions.retain(|extension| {
                extension.extension_type != ext_type::QUIC_TRANSPORT_PARAMETERS
            });
        }
        let mut handshake = Tls13Handshake::new(profile, "localhost");
        if quic {
            handshake.enable_quic_mode();
            handshake.set_quic_transport_parameters(Vec::new());
        }
        let mut ticket = test_psk_ticket(false);
        ticket.alpn = Some("h3".into());
        ticket.max_early_data_size = u32::MAX;
        handshake.set_psk_ticket(ticket);
        let hello = handshake.build_client_hello().unwrap();
        assert_eq!(
            client_hello_extension(&hello, ext_type::EARLY_DATA),
            Some(Vec::new())
        );
        handshake
    }

    fn early_data_test_server_hello(handshake: &mut Tls13Handshake, cipher: u16, psk: bool) {
        let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
        extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&[0, 29]);
        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key.public_key);
        if psk {
            extensions.extend_from_slice(&[0, 41, 0, 2, 0, 0]);
        }
        let mut hello = build_hrr(handshake.session_id.as_ref().unwrap(), cipher, &extensions);
        hello[6..38].fill(0x55);
        assert!(matches!(
            handshake.process_handshake_record(&hello).unwrap(),
            HandshakeAction::InstallHandshakeKeys(_)
        ));
    }

    fn early_data_test_extensions(
        quic: bool,
        alpn: Option<&str>,
        early_data: Option<Vec<u8>>,
        early_data_first: bool,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(alpn) = alpn {
            let mut data = ((alpn.len() + 1) as u16).to_be_bytes().to_vec();
            data.push(alpn.len() as u8);
            data.extend_from_slice(alpn.as_bytes());
            extensions.push((ext_type::ALPN, data));
        }
        if quic {
            extensions.push((ext_type::QUIC_TRANSPORT_PARAMETERS, Vec::new()));
        }
        if let Some(data) = early_data {
            if early_data_first {
                extensions.insert(0, (ext_type::EARLY_DATA, data));
            } else {
                extensions.push((ext_type::EARLY_DATA, data));
            }
        }
        encrypted_extensions_message(&extensions)
    }

    #[test]
    fn early_data_offer_uses_the_complete_psk_client_hello_transcript() {
        for ech in [false, true] {
            let mut handshake = Tls13Handshake::new(
                crate::profile::presets::chrome_155_quic(),
                "private.example.com",
            );
            handshake.enable_quic_mode();
            handshake.set_quic_transport_parameters(Vec::new());
            if ech {
                handshake.set_ech_config(build_test_ech_config_list());
            }
            let mut ticket = test_psk_ticket(false);
            ticket.alpn = Some("h3".into());
            ticket.max_early_data_size = u32::MAX;
            handshake.set_psk_ticket(ticket);
            assert!(handshake.early_data_offer().is_none());
            let outer = handshake.build_client_hello().unwrap();
            let (ticket, transcript) = handshake.early_data_offer().unwrap();
            if ech {
                assert_eq!(transcript, handshake.ech_inner_hello.as_deref().unwrap());
                assert_ne!(transcript, outer);
                assert!(client_hello_extension(&outer, ext_type::PRE_SHARED_KEY).is_none());
            } else {
                assert_eq!(transcript, outer);
            }
            let psk = client_hello_extension(transcript, ext_type::PRE_SHARED_KEY).unwrap();
            let binder = psk_binder(&psk);
            let truncated_len = transcript.len()
                - pre_shared_key::binders_size(1, ticket.hkdf_algorithm.hash_len());
            let mut hash = TranscriptHash::new(ticket.hkdf_algorithm);
            hash.update(&transcript[..truncated_len]);
            assert_eq!(
                binder,
                pre_shared_key::compute_psk_binder(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                    &hash.current_hash(),
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn early_data_offer_requires_a_serialized_empty_extension_and_ticket() {
        for case in 0..4 {
            let mut profile = crate::profile::presets::chrome_155_quic();
            if case == 2 {
                profile
                    .extensions
                    .retain(|extension| extension.extension_type != ext_type::EARLY_DATA);
            } else if case == 3 {
                profile
                    .extensions
                    .iter_mut()
                    .find(|extension| extension.extension_type == ext_type::EARLY_DATA)
                    .unwrap()
                    .source = ExtensionSource::RawBytes { data: "00".into() };
            }
            let mut handshake = Tls13Handshake::new(profile, "localhost");
            handshake.enable_quic_mode();
            handshake.set_quic_transport_parameters(Vec::new());
            if case != 0 {
                let mut ticket = test_psk_ticket(false);
                ticket.max_early_data_size = if case == 1 { 0 } else { u32::MAX };
                handshake.set_psk_ticket(ticket);
            }
            handshake.build_client_hello().unwrap();
            assert!(handshake.early_data_offer().is_none(), "case={case}");
        }
    }

    #[test]
    fn alps_ticket_state_changed_settings_remove_early_data_from_both_ech_hellos() {
        let mut handshake = Tls13Handshake::new(
            crate::profile::presets::chrome_155_quic(),
            "private.example.com",
        );
        handshake.enable_quic_mode();
        handshake.set_quic_transport_parameters(Vec::new());
        handshake.set_ech_config(build_test_ech_config_list());
        handshake.set_alps_payload(vec![6, 0x40, 0x80]);
        let mut ticket = test_psk_ticket(false);
        ticket.alpn = Some("h3".into());
        ticket.max_early_data_size = u32::MAX;
        ticket.alps = AlpsSessionState::Negotiated {
            client_settings: vec![6, 0x40, 0x40],
            server_settings: vec![6, 0x41, 0],
        };
        handshake.set_psk_ticket(ticket);
        let outer = handshake.build_client_hello().unwrap();
        let inner = handshake.ech_inner_hello.as_deref().unwrap();
        assert!(client_hello_extension(&outer, ext_type::EARLY_DATA).is_none());
        assert!(client_hello_extension(inner, ext_type::EARLY_DATA).is_none());
        assert!(client_hello_extension(inner, ext_type::PRE_SHARED_KEY).is_some());
        assert!(handshake.early_data_offer().is_none());
    }

    #[test]
    fn early_data_acceptance_rejects_nonempty_payload() {
        for quic in [false, true] {
            for payload in [vec![0], vec![0, 0, 0, 0]] {
                let mut handshake = early_data_test_handshake(quic);
                early_data_test_server_hello(&mut handshake, 0x1301, true);
                let message = early_data_test_extensions(quic, Some("h3"), Some(payload), true);
                let result = handshake.process_handshake_record(&message);
                assert!(
                    matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError),
                    "quic={quic}: nonempty early_data must be decode_error"
                );
                assert!(!handshake.early_data_accepted);
            }
        }
    }

    #[test]
    fn early_data_acceptance_requires_selected_psk() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake(quic);
            early_data_test_server_hello(&mut handshake, 0x1301, false);
            let message = early_data_test_extensions(quic, Some("h3"), Some(Vec::new()), true);
            let result = handshake.process_handshake_record(&message);
            assert!(
                matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::UnsupportedExtension),
                "quic={quic}: early_data without resumed PSK must be unsupported_extension"
            );
            assert!(!handshake.early_data_accepted);
        }
    }

    #[test]
    fn early_data_nss_acceptance_rejects_nonempty_payload_with_handshake_failure() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake_with_profile(
                quic,
                crate::profile::presets::firefox_156(),
            );
            early_data_test_server_hello(&mut handshake, 0x1301, true);
            let message = early_data_test_extensions(quic, Some("h3"), Some(vec![0]), true);
            let result = handshake.process_handshake_record(&message);
            assert!(
                matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::HandshakeFailure),
                "quic={quic}: NSS reports nonempty early_data with handshake_failure"
            );
            assert!(!handshake.early_data_accepted);
        }
    }

    #[test]
    fn early_data_nss_acceptance_requires_selected_psk_with_illegal_parameter() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake_with_profile(
                quic,
                crate::profile::presets::firefox_156(),
            );
            early_data_test_server_hello(&mut handshake, 0x1301, false);
            let message = early_data_test_extensions(quic, Some("h3"), Some(Vec::new()), true);
            let result = handshake.process_handshake_record(&message);
            assert!(
                matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter),
                "quic={quic}: NSS reports accepted early_data without PSK with illegal_parameter"
            );
            assert!(!handshake.early_data_accepted);
        }
    }

    #[test]
    fn early_data_acceptance_requires_original_cipher_suite() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake(quic);
            early_data_test_server_hello(&mut handshake, 0x1303, true);
            let message = early_data_test_extensions(quic, Some("h3"), Some(Vec::new()), true);
            let result = handshake.process_handshake_record(&message);
            assert!(
                matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter),
                "quic={quic}: equal PSK hashes do not permit an early_data cipher change"
            );
            assert!(!handshake.early_data_accepted);
        }
    }

    #[test]
    fn early_data_acceptance_requires_original_alpn() {
        for quic in [false, true] {
            for alpn in [Some("h2"), None] {
                for early_data_first in [false, true] {
                    let mut handshake = early_data_test_handshake(quic);
                    early_data_test_server_hello(&mut handshake, 0x1301, true);
                    let message =
                        early_data_test_extensions(quic, alpn, Some(Vec::new()), early_data_first);
                    let result = handshake.process_handshake_record(&message);
                    assert!(
                        matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter),
                        "quic={quic} alpn={alpn:?}: accepted early_data must retain the ticket ALPN"
                    );
                    assert!(!handshake.early_data_accepted);
                }
            }
        }
    }

    #[test]
    fn early_data_acceptance_retains_valid_acceptance_and_rejection() {
        for quic in [false, true] {
            for early_data_first in [false, true] {
                let mut handshake = early_data_test_handshake(quic);
                early_data_test_server_hello(&mut handshake, 0x1301, true);
                let message = early_data_test_extensions(
                    quic,
                    Some("h3"),
                    Some(Vec::new()),
                    early_data_first,
                );
                assert!(matches!(
                    handshake.process_handshake_record(&message).unwrap(),
                    HandshakeAction::ContinueReading
                ));
                assert!(handshake.early_data_accepted);
                assert_eq!(handshake.state(), Tls13State::WaitFinished);
            }
            for resumed in [false, true] {
                let mut handshake = early_data_test_handshake(quic);
                early_data_test_server_hello(&mut handshake, 0x1303, resumed);
                let message = early_data_test_extensions(quic, Some("h2"), None, false);
                assert!(matches!(
                    handshake.process_handshake_record(&message).unwrap(),
                    HandshakeAction::ContinueReading
                ));
                assert!(!handshake.early_data_accepted);
                assert_eq!(
                    handshake.state(),
                    if resumed {
                        Tls13State::WaitFinished
                    } else {
                        Tls13State::WaitCertificate
                    }
                );
            }
        }
    }

    #[test]
    fn early_data_end_of_flight_uses_tcp_acceptance_in_finished_transcript() {
        for quic in [false, true] {
            for accepted in [false, true] {
                let mut handshake = early_data_test_handshake(quic);
                early_data_test_server_hello(&mut handshake, 0x1301, true);
                let encrypted_extensions =
                    early_data_test_extensions(quic, Some("h3"), accepted.then(Vec::new), true);
                handshake
                    .process_handshake_record(&encrypted_extensions)
                    .unwrap();
                let mut expected_transcript = handshake.transcript.clone().unwrap();
                let client_hs_secret = handshake.client_hs_traffic_secret.clone().unwrap();
                let server_verify = compute_finished_verify_data(
                    HkdfAlgorithm::Sha256,
                    handshake.server_hs_traffic_secret.as_ref().unwrap(),
                    &expected_transcript.current_hash(),
                )
                .unwrap();
                let mut server_finished =
                    vec![handshake_type::FINISHED, 0, 0, server_verify.len() as u8];
                server_finished.extend_from_slice(&server_verify);
                expected_transcript.update(&server_finished);
                if accepted && !quic {
                    expected_transcript.update(&[5, 0, 0, 0]);
                }
                let expected_client_verify = compute_finished_verify_data(
                    HkdfAlgorithm::Sha256,
                    &client_hs_secret,
                    &expected_transcript.current_hash(),
                )
                .unwrap();
                let HandshakeAction::Complete(complete) = handshake
                    .process_handshake_record(&server_finished)
                    .unwrap()
                else {
                    panic!("valid server Finished must complete the handshake");
                };
                assert_eq!(
                    complete.client_end_of_early_data.is_some(),
                    accepted && !quic
                );
                if let Some(early) = complete.client_end_of_early_data {
                    assert_eq!(early.message, [5, 0, 0, 0]);
                    assert_eq!(early.client_key.len(), 16);
                    assert_eq!(early.client_iv.len(), 12);
                }
                assert_eq!(&complete.client_finished[4..], expected_client_verify);
            }
        }
    }

    fn early_flight_combination_start(quic: bool, alps_code_point: u16) -> Tls13Handshake {
        let mut profile = if quic {
            crate::profile::presets::chrome_155_quic()
        } else {
            crate::profile::presets::chrome_155()
        };
        let alpn = if quic { "h3" } else { "h2" };
        profile.alpn_protocols = vec![alpn.into()];
        profile.alps_protocols = Some(vec![alpn.into()]);
        profile.extensions.retain(|extension| {
            !matches!(
                extension.extension_type,
                0x4469 | 0x44cd | ext_type::EARLY_DATA
            )
        });
        profile.extensions.extend([
            ExtensionSpec {
                extension_type: alps_code_point,
                source: ExtensionSource::Auto,
            },
            ExtensionSpec {
                extension_type: ext_type::EARLY_DATA,
                source: ExtensionSource::Auto,
            },
        ]);
        let mut handshake = Tls13Handshake::new(profile, "localhost");
        handshake.set_alps_payload(Vec::new());
        if quic {
            handshake.enable_quic_mode();
            handshake.set_quic_transport_parameters(Vec::new());
        }
        let mut ticket = test_psk_ticket(false);
        ticket.alpn = Some(alpn.into());
        ticket.max_early_data_size = if quic { u32::MAX } else { 16_384 };
        handshake.set_psk_ticket(ticket);
        let hello = handshake.build_client_hello().unwrap();
        assert!(client_hello_extension(&hello, alps_code_point).is_some());
        assert_eq!(
            client_hello_extension(&hello, ext_type::EARLY_DATA),
            Some(Vec::new())
        );
        handshake
    }

    fn early_flight_combination_ee(
        quic: bool,
        alps_code_point: u16,
        accept_early: bool,
        early_first: bool,
    ) -> Vec<u8> {
        let mut extensions = vec![
            (
                ext_type::ALPN,
                vec![0, 3, 2, b'h', if quic { b'3' } else { b'2' }],
            ),
            (alps_code_point, Vec::new()),
        ];
        if quic {
            extensions.push((ext_type::QUIC_TRANSPORT_PARAMETERS, Vec::new()));
        }
        if accept_early {
            let early = (ext_type::EARLY_DATA, Vec::new());
            if early_first {
                extensions.insert(0, early);
            } else {
                extensions.push(early);
            }
        }
        encrypted_extensions_message(&extensions)
    }

    fn early_flight_combination_message(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(payload);
        message
    }

    #[test]
    fn early_flight_combination_rejects_fresh_alps_with_accepted_early_data() {
        let mut mismatches = Vec::new();
        for quic in [false, true] {
            for alps in [0x4469, 0x44cd] {
                for early_first in [false, true] {
                    let mut handshake = early_flight_combination_start(quic, alps);
                    early_data_test_server_hello(&mut handshake, 0x1301, true);
                    let message = early_flight_combination_ee(quic, alps, true, early_first);
                    let result = handshake.process_handshake_record(&message);
                    let alert = match result.as_ref().err() {
                        Some(TlsError::LocalAlert { alert, .. }) => Some(alert.description),
                        _ => None,
                    };
                    if alert != Some(AlertDescription::IllegalParameter) {
                        mismatches.push(format!(
                            "quic={quic} alps=0x{alps:04x} early_first={early_first} accepted={} alert={alert:?}",
                            result.is_ok(),
                        ));
                    }
                }
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn early_flight_combination_psk_acceptance_rejects_main_handshake_certificate_request() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake(quic);
            early_data_test_server_hello(&mut handshake, 0x1301, true);
            let ee = early_data_test_extensions(quic, Some("h3"), Some(Vec::new()), true);
            handshake.process_handshake_record(&ee).unwrap();
            let request = early_flight_combination_message(
                handshake_type::CERTIFICATE_REQUEST,
                &[0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3],
            );
            assert!(matches!(
                handshake.process_handshake_record(&request),
                Err(TlsError::UnexpectedMessage(_))
            ));
            assert!(handshake.client_certificate_request_context.is_none());
        }
    }

    #[test]
    fn early_flight_combination_rejected_psk_keeps_alps_and_certificate_transcript_order() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        let anchor = crate::verify::certchain::parse_trust_anchor_from_der(cert.der()).unwrap();
        let signer = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &signing_key.serialize_der(),
        )
        .unwrap();

        for quic in [false, true] {
            for alps in [0x4469, 0x44cd] {
                let mut handshake = early_flight_combination_start(quic, alps);
                handshake.set_custom_ca_anchors(Arc::new(vec![anchor.clone()]));
                early_data_test_server_hello(&mut handshake, 0x1301, false);
                let ee = early_flight_combination_ee(quic, alps, false, false);
                handshake.process_handshake_record(&ee).unwrap();
                let request = early_flight_combination_message(
                    handshake_type::CERTIFICATE_REQUEST,
                    &[0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3],
                );
                handshake.process_handshake_record(&request).unwrap();

                let cert_der = cert.der().as_ref();
                let mut certificate = vec![0];
                certificate.extend_from_slice(&((cert_der.len() + 5) as u32).to_be_bytes()[1..]);
                certificate.extend_from_slice(&(cert_der.len() as u32).to_be_bytes()[1..]);
                certificate.extend_from_slice(cert_der);
                certificate.extend_from_slice(&[0, 0]);
                handshake
                    .process_handshake_record(&early_flight_combination_message(
                        handshake_type::CERTIFICATE,
                        &certificate,
                    ))
                    .unwrap();
                let mut signed = vec![0x20; 64];
                signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                signed.extend_from_slice(&handshake.transcript.as_ref().unwrap().current_hash());
                let signature = signer.sign(&SystemRandom::new(), &signed).unwrap();
                let mut verify = vec![4, 3];
                verify.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
                verify.extend_from_slice(signature.as_ref());
                handshake
                    .process_handshake_record(&early_flight_combination_message(
                        handshake_type::CERTIFICATE_VERIFY,
                        &verify,
                    ))
                    .unwrap();

                let mut expected_transcript = handshake.transcript.clone().unwrap();
                let server_verify = compute_finished_verify_data(
                    HkdfAlgorithm::Sha256,
                    handshake.server_hs_traffic_secret.as_ref().unwrap(),
                    &expected_transcript.current_hash(),
                )
                .unwrap();
                let server_finished =
                    early_flight_combination_message(handshake_type::FINISHED, &server_verify);
                let expected_cee = encrypted_extensions_message(&[(alps, Vec::new())]);
                let expected_certificate = vec![handshake_type::CERTIFICATE, 0, 0, 4, 0, 0, 0, 0];
                expected_transcript.update(&server_finished);
                expected_transcript.update(&expected_cee);
                expected_transcript.update(&expected_certificate);
                let expected_client_verify = compute_finished_verify_data(
                    HkdfAlgorithm::Sha256,
                    handshake.client_hs_traffic_secret.as_ref().unwrap(),
                    &expected_transcript.current_hash(),
                )
                .unwrap();
                let HandshakeAction::Complete(complete) = handshake
                    .process_handshake_record(&server_finished)
                    .unwrap()
                else {
                    panic!("valid certificate-authenticated handshake must complete");
                };
                assert!(!complete.early_data_accepted);
                assert!(complete.client_end_of_early_data.is_none());
                assert_eq!(
                    complete.client_encrypted_extensions.as_ref(),
                    Some(&expected_cee)
                );
                assert_eq!(
                    complete.client_certificate.as_ref(),
                    Some(&expected_certificate)
                );
                assert_eq!(&complete.client_finished[4..], expected_client_verify);
            }
        }
    }

    #[test]
    fn early_data_acceptance_is_unsolicited_after_hello_retry_request() {
        for quic in [false, true] {
            let mut handshake = early_data_test_handshake(quic);
            assert!(handshake.early_data_offer().is_some());
            assert_eq!(handshake.client_end_of_early_data.is_some(), !quic);
            let retry = build_hrr(
                handshake.session_id.as_ref().unwrap(),
                0x1301,
                &[0, 43, 0, 2, 3, 4, 0, 44, 0, 3, 0, 1, 0xa5],
            );
            let HandshakeAction::RetryClientHello(hello) =
                handshake.process_handshake_record(&retry).unwrap()
            else {
                panic!("expected cookie-only HelloRetryRequest");
            };
            assert!(handshake.early_data_offer().is_none());
            assert!(handshake.client_end_of_early_data.is_none());
            assert!(client_hello_extension(&hello, ext_type::EARLY_DATA).is_none());
            early_data_test_server_hello(&mut handshake, 0x1301, true);
            let message = early_data_test_extensions(quic, Some("h3"), Some(Vec::new()), true);
            assert!(matches!(
                handshake.process_handshake_record(&message),
                Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == AlertDescription::UnsupportedExtension
            ));
            assert!(!handshake.early_data_accepted);
        }
    }

    #[test]
    fn missing_alpn_is_allowed_on_tcp_but_not_after_a_quic_offer() {
        for quic in [false, true] {
            let mut profile = crate::profile::presets::chrome_155();
            profile.alpn_protocols = vec!["h3".into()];
            let mut handshake = Tls13Handshake::new(profile, "example.com");
            if quic {
                handshake.enable_quic_mode();
                handshake.set_quic_transport_parameters(Vec::new());
            }
            handshake.build_client_hello().unwrap();
            let fields = if quic {
                vec![(ext_type::QUIC_TRANSPORT_PARAMETERS, Vec::new())]
            } else {
                Vec::new()
            };
            let message = encrypted_extensions_message(&fields);
            let result = handshake.process_encrypted_extensions(&message, &message[4..]);
            if quic {
                assert!(
                    matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::NoApplicationProtocol)
                );
            } else {
                assert!(matches!(result.unwrap(), HandshakeAction::ContinueReading));
                assert!(handshake.negotiated_alpn.is_none());
            }
        }
    }

    #[test]
    fn quic_without_an_alpn_offer_allows_out_of_band_negotiation() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.alpn_protocols.clear();
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.enable_quic_mode();
        handshake.set_quic_transport_parameters(Vec::new());
        handshake.build_client_hello().unwrap();
        let message =
            encrypted_extensions_message(&[(ext_type::QUIC_TRANSPORT_PARAMETERS, Vec::new())]);
        assert!(matches!(
            handshake
                .process_encrypted_extensions(&message, &message[4..])
                .unwrap(),
            HandshakeAction::ContinueReading
        ));
        assert!(handshake.negotiated_alpn.is_none());
    }

    #[test]
    fn malformed_server_alpn_is_decode_error() {
        for payload in [
            vec![],
            vec![0, 0],
            vec![0, 2, 0, 0],
            vec![0, 2, 2, b'h', b'2'],
            vec![0, 4, 2, b'h', b'2', 0],
            vec![0, 6, 2, b'h', b'2', 2, b'h', b'3'],
        ] {
            let mut handshake =
                Tls13Handshake::new(crate::profile::presets::chrome_155(), "example.com");
            handshake.build_client_hello().unwrap();
            let message = encrypted_extensions_message(&[(ext_type::ALPN, payload)]);
            assert!(
                matches!(handshake.process_encrypted_extensions(&message, &message[4..]), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
            );
        }
    }

    #[test]
    fn encrypted_extensions_invalid_framing_is_decode_error() {
        for message in [
            vec![8, 0, 0, 0],
            vec![8, 0, 0, 1, 0],
            vec![8, 0, 0, 3, 0, 0, 0],
            vec![8, 0, 0, 4, 0, 2, 0, 16],
            vec![8, 0, 0, 6, 0, 4, 0, 16, 0, 5],
        ] {
            let mut handshake =
                Tls13Handshake::new(crate::profile::presets::chrome_155(), "example.com");
            handshake.build_client_hello().unwrap();
            assert!(
                matches!(handshake.process_encrypted_extensions(&message, &message[4..]), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
            );
        }
    }

    #[test]
    fn alpn_selection_matches_actual_raw_offer_bytes() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.alpn_protocols = vec!["h2".into()];
        profile
            .extensions
            .iter_mut()
            .find(|extension| extension.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "00020180".into(),
        };
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let message = encrypted_extensions_message(&[(ext_type::ALPN, vec![0, 2, 1, 0x80])]);
        assert!(matches!(
            handshake
                .process_encrypted_extensions(&message, &message[4..])
                .unwrap(),
            HandshakeAction::ContinueReading
        ));
        assert_eq!(
            handshake.offered_alpn_protocols.as_ref().unwrap(),
            &vec![vec![0x80]]
        );
    }

    // -----------------------------------------------------------------------
    // RFC 8449 `record_size_limit` in EncryptedExtensions
    // -----------------------------------------------------------------------

    /// Build an EncryptedExtensions handshake message carrying `extensions`.
    fn encrypted_extensions_message(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut block = Vec::new();
        for (ext_type, data) in extensions {
            block.extend_from_slice(&ext_type.to_be_bytes());
            block.extend_from_slice(&(data.len() as u16).to_be_bytes());
            block.extend_from_slice(data);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(block.len() as u16).to_be_bytes());
        body.extend_from_slice(&block);

        let mut message = vec![handshake_type::ENCRYPTED_EXTENSIONS];
        let body_len = body.len();
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    /// A Firefox handshake that has already sent its ClientHello, so
    /// `record_size_limit` counts as an offered extension.
    fn firefox_handshake_after_client_hello() -> Tls13Handshake {
        let profile = crate::profile::presets::firefox_147();
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        assert!(
            handshake
                .offered_extensions
                .as_ref()
                .is_some_and(|offered| offered.contains(&ext_type::RECORD_SIZE_LIMIT)),
            "test premise: the Firefox ClientHello offers record_size_limit"
        );
        handshake
    }

    /// RFC 8449 §4: "In TLS 1.3, the server sends the 'record_size_limit'
    /// extension in the EncryptedExtensions message." We must read it.
    #[test]
    fn encrypted_extensions_record_size_limit_is_recorded() {
        let mut handshake = firefox_handshake_after_client_hello();
        assert_eq!(
            handshake.peer_record_size_limit, None,
            "no limit is known before EncryptedExtensions"
        );

        let message =
            encrypted_extensions_message(&[(ext_type::RECORD_SIZE_LIMIT, vec![0x02, 0x00])]);
        handshake
            .process_encrypted_extensions(&message, &message[4..])
            .unwrap();

        assert_eq!(
            handshake.peer_record_size_limit,
            Some(512),
            "the server's record_size_limit must be captured from EncryptedExtensions"
        );
    }

    /// A server that stays quiet leaves us at the protocol maximum.
    #[test]
    fn encrypted_extensions_without_record_size_limit_leaves_it_unset() {
        let mut handshake = firefox_handshake_after_client_hello();
        let message =
            encrypted_extensions_message(&[(ext_type::ALPN, vec![0x00, 0x03, 0x02, b'h', b'2'])]);
        handshake
            .process_encrypted_extensions(&message, &message[4..])
            .unwrap();

        assert_eq!(handshake.peer_record_size_limit, None);
        assert_eq!(handshake.negotiated_alpn.as_deref(), Some("h2"));
    }

    /// RFC 8449 §4: "An endpoint MUST treat receipt of a smaller value [than
    /// 64] as a fatal error and generate an 'illegal_parameter' alert."
    #[test]
    fn encrypted_extensions_record_size_limit_below_64_is_illegal_parameter() {
        for raw in [0u16, 1, 63] {
            let mut handshake = firefox_handshake_after_client_hello();
            let message = encrypted_extensions_message(&[(
                ext_type::RECORD_SIZE_LIMIT,
                raw.to_be_bytes().to_vec(),
            )]);
            let error = handshake
                .process_encrypted_extensions(&message, &message[4..])
                .expect_err("a record_size_limit below 64 must abort the handshake");
            let description = error.as_alert().map(|alert| alert.description);
            assert_eq!(
                description,
                Some(AlertDescription::IllegalParameter),
                "value {raw} must abort with illegal_parameter, got {description:?}"
            );
            assert_eq!(
                handshake.peer_record_size_limit, None,
                "a rejected value must not be stored"
            );
        }
    }

    #[test]
    fn encrypted_extensions_record_size_limit_at_64_is_accepted() {
        let mut handshake = firefox_handshake_after_client_hello();
        let message = encrypted_extensions_message(&[(
            ext_type::RECORD_SIZE_LIMIT,
            64u16.to_be_bytes().to_vec(),
        )]);

        handshake
            .process_encrypted_extensions(&message, &message[4..])
            .expect("the RFC 8449 minimum record_size_limit is legal");

        assert_eq!(handshake.peer_record_size_limit, Some(64));
    }
    #[test]
    fn test_hrr_rejects_group_already_offered_in_key_share() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let already_offered = profile.key_share_curves[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();

        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
        extensions.extend_from_slice(&already_offered.to_be_bytes());
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let error = handshake.process_handshake_record(&hrr).unwrap_err();
        assert!(error
            .to_string()
            .contains("already present in CH1 key_share"));
    }

    #[test]
    fn test_hrr_rejects_no_requested_change() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();
        let extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let error = handshake.process_handshake_record(&hrr).unwrap_err();
        assert!(error
            .to_string()
            .contains("would not change the second ClientHello"));
    }

    #[test]
    fn test_quic_hrr_preserves_transport_parameters_and_empty_session_id() {
        let mut profile = crate::profile::presets::chrome_150();
        profile.alpn_protocols = vec!["h3".to_string()];
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.enable_quic_mode();
        handshake.set_quic_transport_parameters(vec![0x01, 0x02, 0x03, 0x04]);
        let ch1 = handshake.build_client_hello().unwrap();
        assert_eq!(ch1[38], 0, "QUIC CH1 legacy_session_id must be empty");

        let session_id = handshake.session_id.clone().unwrap();
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x18]);
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2) = action else {
            panic!("expected retry ClientHello");
        };
        assert_eq!(ch2[38], 0, "QUIC CH2 legacy_session_id must remain empty");
        assert_eq!(
            client_hello_extension(&ch2, ext_type::QUIC_TRANSPORT_PARAMETERS),
            client_hello_extension(&ch1, ext_type::QUIC_TRANSPORT_PARAMETERS),
        );
    }

    #[test]
    fn test_ech_psk_hrr_binders_cover_inner_client_hellos() {
        use crate::session_store::TicketTlsVersion;
        use std::time::Instant;

        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = 0x1301;
        let resumption_psk = vec![0xA5; 32];
        let ticket = SessionTicketData {
            ticket: b"ech-psk-hrr-ticket".to_vec(),
            resumption_psk: resumption_psk.clone(),
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite,
            lifetime_secs: 3600,
            age_add: 0x1020_3040,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        };
        let mut handshake = Tls13Handshake::new(profile, "secret.example.com");
        handshake.set_ech_config(build_test_ech_config_list());
        handshake.set_psk_ticket(ticket);

        let ch1_outer = handshake.build_client_hello().unwrap();
        let ch1_inner = handshake.ech_inner_hello.clone().expect("ECH inner CH1");
        assert!(client_hello_extension(&ch1_outer, ext_type::PRE_SHARED_KEY).is_none());
        assert_eq!(
            client_hello_extension_types(&ch1_inner).last(),
            Some(&ext_type::PRE_SHARED_KEY),
        );
        let ch1_psk = client_hello_extension(&ch1_inner, ext_type::PRE_SHARED_KEY).unwrap();
        let ch1_binder = psk_binder(&ch1_psk);
        let ch1_truncated_len =
            ch1_inner.len() - pre_shared_key::binders_size(1, HkdfAlgorithm::Sha256.hash_len());
        let ch1_hash = digest::digest(&digest::SHA256, &ch1_inner[..ch1_truncated_len]);
        let expected_ch1_binder = pre_shared_key::compute_psk_binder(
            HkdfAlgorithm::Sha256,
            &resumption_psk,
            ch1_hash.as_ref(),
        )
        .unwrap();
        assert_eq!(ch1_binder, expected_ch1_binder);

        let session_id = handshake.session_id.clone().unwrap();
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x18]);
        extensions.extend_from_slice(&[0xfe, 0x0d, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut hrr = build_hrr(&session_id, cipher_suite, &extensions);
        let first_hash = digest::digest(&digest::SHA256, &ch1_inner);
        let mut confirmation_hash = digest::Context::new(&digest::SHA256);
        confirmation_hash.update(&[0xfe, 0, 0, 32]);
        confirmation_hash.update(first_hash.as_ref());
        confirmation_hash.update(&hrr);
        let secret = hkdf_extract(HkdfAlgorithm::Sha256, &[0; 32], &ch1_inner[6..38]).unwrap();
        let signal = secret
            .expand_label(
                "hrr ech accept confirmation",
                confirmation_hash.finish().as_ref(),
                8,
            )
            .unwrap();
        let signal_offset = hrr.len() - 8;
        hrr[signal_offset..].copy_from_slice(&signal);
        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2_outer) = action else {
            panic!("expected retry ClientHello");
        };
        let ch2_inner = handshake.hrr_inner_ch2.clone().expect("ECH inner CH2");
        assert_eq!(handshake.ech_hrr_accepted, Some(true));

        assert!(client_hello_extension(&ch2_outer, ext_type::PRE_SHARED_KEY).is_none());
        assert!(client_hello_extension(&ch2_outer, ext_type::EARLY_DATA).is_none());
        assert!(client_hello_extension(&ch2_inner, ext_type::EARLY_DATA).is_none());
        assert_eq!(
            client_hello_extension_types(&ch2_inner).last(),
            Some(&ext_type::PRE_SHARED_KEY),
        );
        let ch2_psk = client_hello_extension(&ch2_inner, ext_type::PRE_SHARED_KEY).unwrap();
        let ch2_binder = psk_binder(&ch2_psk);
        let ch2_truncated_len =
            ch2_inner.len() - pre_shared_key::binders_size(1, HkdfAlgorithm::Sha256.hash_len());
        let prefix =
            Tls13Handshake::ech_hrr_psk_transcript_prefix(HkdfAlgorithm::Sha256, &ch1_inner, &hrr);
        let mut transcript = digest::Context::new(&digest::SHA256);
        transcript.update(&prefix);
        transcript.update(&ch2_inner[..ch2_truncated_len]);
        let expected_ch2_binder = pre_shared_key::compute_psk_binder(
            HkdfAlgorithm::Sha256,
            &resumption_psk,
            transcript.finish().as_ref(),
        )
        .unwrap();
        assert_eq!(ch2_binder, expected_ch2_binder);
    }

    #[test]
    fn accepted_ech_hrr_cookie_uses_message_hash_and_reaches_inner_ch2() {
        for (cipher_suite, hkdf_algo, hash_algorithm) in [
            (0x1301, HkdfAlgorithm::Sha256, &digest::SHA256),
            (0x1302, HkdfAlgorithm::Sha384, &digest::SHA384),
        ] {
            for quic in [false, true] {
                for ticket_mode in 0..3 {
                    for final_accepts in [false, true] {
                        let mut handshake = Tls13Handshake::new(
                            crate::profile::presets::chrome_155(),
                            "secret.example.com",
                        );
                        if quic {
                            handshake.enable_quic_mode();
                            handshake.set_quic_transport_parameters(vec![1, 1, 0]);
                        }
                        handshake.set_ech_config(build_test_ech_config_list());
                        if ticket_mode != 0 {
                            let sha384 = if ticket_mode == 1 {
                                cipher_suite == 0x1302
                            } else {
                                cipher_suite != 0x1302
                            };
                            handshake.set_psk_ticket(test_psk_ticket(sha384));
                        }
                        handshake.build_client_hello().unwrap();
                        let inner1 = handshake.ech_inner_hello.clone().unwrap();
                        let cookie = b"accepted-ech-cookie";
                        let mut extensions = vec![0, 43, 0, 2, 3, 4];
                        extensions.extend_from_slice(&ext_type::COOKIE.to_be_bytes());
                        extensions.extend_from_slice(&((2 + cookie.len()) as u16).to_be_bytes());
                        extensions.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
                        extensions.extend_from_slice(cookie);
                        extensions.extend_from_slice(&[0xfe, 0x0d, 0, 8]);
                        extensions.extend_from_slice(&[0; 8]);
                        let mut hrr = build_hrr(
                            handshake.session_id.as_ref().unwrap(),
                            cipher_suite,
                            &extensions,
                        );

                        // Construct the peer's transcript explicitly, independently of the
                        // client's confirmation checker: message_hash(CH1) || zeroed HRR.
                        let hash1 = digest::digest(hash_algorithm, &inner1);
                        let mut context = digest::Context::new(hash_algorithm);
                        context.update(&[0xfe, 0, 0, hash1.as_ref().len() as u8]);
                        context.update(hash1.as_ref());
                        context.update(&hrr);
                        let secret =
                            hkdf_extract(hkdf_algo, &vec![0; hkdf_algo.hash_len()], &inner1[6..38])
                                .unwrap();
                        let confirmation = secret
                            .expand_label(
                                "hrr ech accept confirmation",
                                context.finish().as_ref(),
                                8,
                            )
                            .unwrap();
                        let offset = hrr.len() - 8;
                        hrr[offset..].copy_from_slice(&confirmation);
                        let mut corrupted: [u8; 8] = confirmation.as_slice().try_into().unwrap();
                        corrupted[0] ^= 1;
                        assert!(!handshake
                            .check_ech_hrr_acceptance(hkdf_algo, &inner1, &hrr, &corrupted)
                            .unwrap());
                        let action = handshake
                            .process_handshake_record(&hrr)
                            .expect("valid peer ECH acceptance must be recognized");
                        assert!(matches!(action, HandshakeAction::RetryClientHello(_)));
                        assert_eq!(handshake.ech_hrr_accepted, Some(true));
                        let inner2 = handshake.hrr_inner_ch2.as_ref().unwrap();
                        assert_eq!(
                            client_hello_extension(inner2, ext_type::PRE_SHARED_KEY).is_some(),
                            ticket_mode == 1
                        );
                        assert_eq!(
                            handshake
                                .offered_extensions
                                .as_ref()
                                .unwrap()
                                .contains(&ext_type::PRE_SHARED_KEY),
                            ticket_mode == 1
                        );
                        let expected = [&(cookie.len() as u16).to_be_bytes()[..], cookie].concat();
                        assert_eq!(
                            client_hello_extension(inner2, ext_type::COOKIE),
                            Some(expected)
                        );
                        assert_eq!(&inner1[6..38], &inner2[6..38]);
                        let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
                        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                        extensions
                            .extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
                        extensions.extend_from_slice(&[0, 29]);
                        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                        extensions.extend_from_slice(&key.public_key);
                        if ticket_mode == 1 {
                            extensions.extend_from_slice(&[0, 41, 0, 2, 0, 0]);
                        }
                        let mut sh = build_hrr(
                            handshake.session_id.as_ref().unwrap(),
                            cipher_suite,
                            &extensions,
                        );
                        sh[6..38].fill(0x55);
                        sh[30..38].fill(0);
                        let mut final_context = digest::Context::new(hash_algorithm);
                        final_context.update(&[0xfe, 0, 0, hash1.as_ref().len() as u8]);
                        final_context.update(hash1.as_ref());
                        final_context.update(&hrr);
                        final_context.update(inner2);
                        final_context.update(&sh);
                        let final_confirmation = secret
                            .expand_label(
                                "ech accept confirmation",
                                final_context.finish().as_ref(),
                                8,
                            )
                            .unwrap();
                        sh[30..38].copy_from_slice(&final_confirmation);
                        if !final_accepts {
                            sh[30] ^= 1;
                        }
                        let result = handshake.process_handshake_record(&sh);
                        if final_accepts {
                            assert!(
                                matches!(&result, Ok(HandshakeAction::InstallHandshakeKeys(_))),
                                "valid final ECH confirmation: {:?}",
                                result.as_ref().err()
                            );
                            assert!(handshake.ech_accepted);
                            assert_eq!(handshake.psk_accepted, ticket_mode == 1);
                        } else {
                            assert!(
                                matches!(&result, Err(TlsError::LocalAlert { alert, .. })
                            if alert.description == AlertDescription::IllegalParameter),
                                "accepted HRR cannot become rejected ECH: installed_keys={} error={:?}",
                                matches!(&result, Ok(HandshakeAction::InstallHandshakeKeys(_))), result.as_ref().err()
                            );
                            assert!(!handshake.psk_accepted);
                            assert!(handshake.client_hs_traffic_secret.is_none());
                            assert!(handshake.server_hs_traffic_secret.is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn first_ech_rejection_never_commits_inner_psk_acceptance() {
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for quic in [false, true] {
                let mut handshake = Tls13Handshake::new(profile.clone(), "secret.example.com");
                if quic {
                    handshake.enable_quic_mode();
                    handshake.set_quic_transport_parameters(Vec::new());
                }
                handshake.set_ech_config(build_test_ech_config_list());
                handshake.set_psk_ticket(test_psk_ticket(false));
                let outer = handshake.build_client_hello().unwrap();
                assert!(client_hello_extension(&outer, 41).is_none());
                assert!(
                    client_hello_extension(handshake.ech_inner_hello.as_ref().unwrap(), 41)
                        .is_some()
                );
                let key = kx::generate_key_pair(KxGroup::X25519).unwrap();
                let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
                extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
                extensions.extend_from_slice(&[0, 29]);
                extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&key.public_key);
                extensions.extend_from_slice(&[0, 41, 0, 2, 0, 0]);
                let mut sh = build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
                sh[6..38].fill(0x55);
                assert!(
                    matches!(handshake.process_handshake_record(&sh), Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == AlertDescription::IllegalParameter)
                );
                assert!(!handshake.ech_accepted);
                assert!(!handshake.psk_accepted);
                assert!(handshake.client_hs_traffic_secret.is_none());
                assert!(handshake.server_hs_traffic_secret.is_none());
            }
        }
    }

    #[test]
    fn hrr_ech_confirmation_mismatch_is_rejection() {
        let mut handshake =
            Tls13Handshake::new(crate::profile::presets::chrome_155(), "secret.example.com");
        handshake.set_ech_config(build_test_ech_config_list());
        handshake.build_client_hello().unwrap();
        let extensions = [
            0, 43, 0, 2, 3, 4, 0, 44, 0, 3, 0, 1, 0xa5, 0xfe, 0x0d, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let hrr = build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
        let action = handshake
            .process_handshake_record(&hrr)
            .expect("nonmatching ECH signal selects outer rejection handshake");
        assert!(matches!(action, HandshakeAction::RetryClientHello(_)));
        assert_eq!(handshake.ech_hrr_accepted, Some(false));
    }

    #[test]
    fn ech_rejected_hrr_forbids_server_psk_selection_with_illegal_parameter() {
        let mut handshake =
            Tls13Handshake::new(crate::profile::presets::chrome_155(), "secret.example.com");
        handshake.set_ech_config(build_test_ech_config_list());
        handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();
        let hrr = build_hrr(
            &session_id,
            0x1301,
            &[0, 43, 0, 2, 3, 4, 0, 44, 0, 3, 0, 1, 0xa5],
        );
        assert!(matches!(
            handshake.process_handshake_record(&hrr).unwrap(),
            HandshakeAction::RetryClientHello(_)
        ));
        let mut server_hello =
            build_hrr(&session_id, 0x1301, &[0, 43, 0, 2, 3, 4, 0, 41, 0, 2, 0, 0]);
        server_hello[6..38].fill(0x55);
        assert!(
            matches!(handshake.process_handshake_record(&server_hello), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
        );
    }

    #[test]
    fn rejected_ech_hrr_reuses_outer_bytes_without_disclosing_inner_psk() {
        for quic in [false, true] {
            for use_psk in [false, true] {
                for key_share_retry in [false, true] {
                    let mut handshake = Tls13Handshake::new(
                        crate::profile::presets::chrome_155(),
                        "secret.example.com",
                    );
                    if quic {
                        handshake.enable_quic_mode();
                        handshake.set_quic_transport_parameters(vec![1, 1, 0]);
                    }
                    handshake.set_ech_config(build_test_ech_config_list());
                    if use_psk {
                        handshake.set_psk_ticket(SessionTicketData {
                            ticket: b"private-inner-ticket".to_vec(),
                            resumption_psk: vec![0xa5; 32],
                            tls_version: crate::session_store::TicketTlsVersion::Tls13,
                            cipher_suite: 0x1301,
                            lifetime_secs: 3600,
                            age_add: 0,
                            received_at: std::time::Instant::now(),
                            alpn: Some("h2".into()),
                            alps: AlpsSessionState::Unknown,
                            hkdf_algorithm: HkdfAlgorithm::Sha256,
                            aead_algorithm: AeadAlgorithm::Aes128Gcm,
                            master_secret: Vec::new(),
                            max_early_data_size: 0,
                            peer_transport_parameters: None,
                            used_extended_master_secret: None,
                        });
                    }
                    let ch1 = handshake.build_client_hello().unwrap();
                    let mut extensions = vec![0, 43, 0, 2, 3, 4];
                    if key_share_retry {
                        extensions.extend_from_slice(&[0, 51, 0, 2, 0, 24]);
                    } else {
                        extensions.extend_from_slice(&[0, 44, 0, 3, 0, 1, 0xa5]);
                    }
                    let hrr =
                        build_hrr(handshake.session_id.as_ref().unwrap(), 0x1301, &extensions);
                    let HandshakeAction::RetryClientHello(ch2) =
                        handshake.process_handshake_record(&hrr).unwrap()
                    else {
                        panic!("expected outer CH2");
                    };
                    assert_eq!(handshake.ech_hrr_accepted, Some(false));
                    assert_eq!(
                        client_hello_extension(&ch2, ext_type::ENCRYPTED_CLIENT_HELLO),
                        client_hello_extension(&ch1, ext_type::ENCRYPTED_CLIENT_HELLO)
                    );
                    assert_eq!(
                        client_hello_extension(&ch2, ext_type::SNI),
                        client_hello_extension(&ch1, ext_type::SNI),
                        "public name stays on outer retry"
                    );
                    assert!(client_hello_extension(&ch2, ext_type::PRE_SHARED_KEY).is_none());
                    assert!(
                        handshake.hrr_inner_ch2.is_none(),
                        "no new inner after rejection"
                    );
                    assert_eq!(
                        handshake.ech_rejection_public_name().as_deref(),
                        Some("public.example.com")
                    );
                }
            }
        }
    }

    #[test]
    fn test_compute_finished_verify_data() {
        let secret = [0x42u8; 32];
        let transcript_hash = [0xAA; 32];
        let vd =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &transcript_hash).unwrap();
        assert_eq!(vd.len(), 32);

        // Same inputs should give same output
        let vd2 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &transcript_hash).unwrap();
        assert_eq!(vd, vd2);
    }

    #[test]
    fn test_parse_certificate_message() {
        // Build a minimal Certificate message
        let cert1 = vec![0x30, 0x82, 0x01, 0x00]; // fake DER cert
        let cert2 = vec![0x30, 0x82, 0x02, 0x00]; // fake intermediate

        let mut payload = Vec::new();
        // certificate_request_context length = 0
        payload.push(0);
        // certificate_list (we'll fill length after)
        let list_start = payload.len();
        payload.extend_from_slice(&[0, 0, 0]); // placeholder

        // cert1 entry
        let cert1_len = cert1.len() as u32;
        payload.push((cert1_len >> 16) as u8);
        payload.push((cert1_len >> 8) as u8);
        payload.push(cert1_len as u8);
        payload.extend_from_slice(&cert1);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        // cert2 entry
        let cert2_len = cert2.len() as u32;
        payload.push((cert2_len >> 16) as u8);
        payload.push((cert2_len >> 8) as u8);
        payload.push(cert2_len as u8);
        payload.extend_from_slice(&cert2);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        // Fill in list length
        let list_len = payload.len() - list_start - 3;
        payload[list_start] = (list_len >> 16) as u8;
        payload[list_start + 1] = (list_len >> 8) as u8;
        payload[list_start + 2] = list_len as u8;

        let certs = parse_certificate_message(&payload).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], cert1);
        assert_eq!(certs[1], cert2);
    }

    // ====================================================================
    // to_hex — debug formatting
    // ====================================================================

    #[test]
    fn hex_encoding_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn hex_encoding_known_bytes() {
        assert_eq!(to_hex(&[0x00, 0xFF, 0x42]), "00ff42");
    }

    // ====================================================================
    // Tls13Handshake — initial state and configuration
    // ====================================================================

    #[test]
    fn new_handshake_starts_at_start_state() {
        let profile = crate::profile::presets::chrome_144();
        let hs = Tls13Handshake::new(profile, "example.com");
        assert_eq!(hs.state(), Tls13State::Start);
    }

    #[test]
    fn configure_for_alps_h2() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_alps_payload(vec![0x00, 0x03, 0x00, 0x64]);
        assert!(hs.alps_payload.is_some());
    }

    /// Real Chrome sends a Client EncryptedExtensions carrying `application_settings`
    /// with an EMPTY payload (verified from a real Chrome 149 capture). Lock that
    /// exact wire encoding for `Some(vec![])`, and the non-empty case for contrast.
    #[test]
    fn client_ee_alps_empty_payload_yields_empty_settings() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        // Server negotiated ALPS with the new code point.
        hs.alps_code_point = Some(0x44CD);

        // Empty client settings (Chrome): EE with a 0-length application_settings.
        hs.alps_payload = Some(Vec::new());
        assert_eq!(
            hs.build_client_encrypted_extensions(),
            // type=0x08, len=0x000006, ext_len=0x0004, ext=0x44CD, data_len=0x0000
            Some(vec![
                0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x44, 0xCD, 0x00, 0x00
            ]),
            "Some(empty) ⇒ Client EE application_settings with 0-length payload"
        );

        // Non-empty client settings are still supported (2-byte payload here).
        hs.alps_payload = Some(vec![0xAA, 0xBB]);
        assert_eq!(
            hs.build_client_encrypted_extensions(),
            Some(vec![
                0x08, 0x00, 0x00, 0x08, 0x00, 0x06, 0x44, 0xCD, 0x00, 0x02, 0xAA, 0xBB
            ]),
            "Some(non-empty) ⇒ payload carried in the Client EE"
        );

        // No payload ⇒ no Client EE at all.
        hs.alps_payload = None;
        assert_eq!(hs.build_client_encrypted_extensions(), None);
    }

    #[test]
    fn configure_insecure_verification() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_verification_policy(VerificationPolicy::Insecure);
        assert_eq!(hs.verification_policy, VerificationPolicy::Insecure);
    }

    #[test]
    fn configure_ech_for_privacy() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        let ech_data = vec![0xFE, 0x0D, 0x00, 0x42];
        hs.set_ech_config(ech_data.clone());
        assert_eq!(hs.ech_config_list, Some(ech_data));
    }

    #[test]
    fn configure_custom_ca_anchors() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_custom_ca_anchors(Arc::new(vec![]));
        assert!(hs.custom_ca_anchors.is_some());
    }

    #[test]
    fn configure_keylog_callback() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured = lines.clone();
        hs.set_keylog_callback(Arc::new(move |line: &str| {
            captured.lock().unwrap().push(line.to_string());
        }));
        assert!(hs.keylog_callback.is_some());
    }

    // ====================================================================
    // decompress_certificate — brotli compressed certificates (RFC 8879)
    // ====================================================================

    /// Zstandard certificate compression (RFC 8879 §7.3). The Firefox profiles
    /// advertise algorithm 3, so a server was free to pick it; without support
    /// the handshake failed with `unsupported certificate compression
    /// algorithm: 3`.
    #[test]
    fn zstd_decompress_round_trip() {
        let original = b"This is a test certificate DER payload for zstd compression.";
        let compressed = zstd::encode_all(&original[..], 3).expect("zstd encode");

        let decompressed = decompress_certificate(3, &compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    /// The declared `uncompressed_length` is authoritative for zstd too: a
    /// mismatch must abort rather than hand back a short or long chain.
    #[test]
    fn zstd_decompress_size_mismatch_fails() {
        let original = b"small data";
        let compressed = zstd::encode_all(&original[..], 3).expect("zstd encode");

        let result = decompress_certificate(3, &compressed, original.len() + 10);
        assert!(result.is_err(), "size mismatch must be rejected");
    }

    #[test]
    fn compressed_certificate_zstd_is_decompressed_and_parsed() {
        let certificate = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let mut certificate_message = vec![0, 0, 0, 0];
        let list_len = 3 + certificate.len() + 2;
        certificate_message[1..4].copy_from_slice(&(list_len as u32).to_be_bytes()[1..4]);
        certificate_message.extend_from_slice(&(certificate.len() as u32).to_be_bytes()[1..4]);
        certificate_message.extend_from_slice(&certificate);
        certificate_message.extend_from_slice(&[0, 0]);

        let compressed = zstd::encode_all(&certificate_message[..], 3).expect("zstd encode");
        let mut payload = Vec::with_capacity(8 + compressed.len());
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&(certificate_message.len() as u32).to_be_bytes()[1..4]);
        payload.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..4]);
        payload.extend_from_slice(&compressed);

        let mut handshake = firefox_handshake_after_client_hello();
        handshake
            .process_compressed_certificate(&[0, 0, 0, payload.len() as u8], &payload)
            .expect("zstd CompressedCertificate must be accepted");

        assert_eq!(handshake.server_certificates, vec![certificate]);
    }
    /// The 256 KiB cap applies to every algorithm, zstd included — a declared
    /// length beyond it is refused before any allocation.
    #[test]
    fn zstd_oversized_declared_length_is_rejected() {
        let compressed = zstd::encode_all(&b"x"[..], 3).expect("zstd encode");
        let result = decompress_certificate(3, &compressed, MAX_DECOMPRESSED_CERT_LEN + 1);
        assert!(
            result.is_err(),
            "oversized declared length must be rejected"
        );
    }

    /// Algorithms we neither advertise nor implement still fail cleanly.
    #[test]
    fn unknown_certificate_compression_algorithm_is_rejected() {
        let result = decompress_certificate(9, b"whatever", 8);
        assert!(result.is_err());
    }

    #[test]
    fn brotli_decompress_round_trip() {
        let original = b"This is a test certificate DER payload for brotli compression.";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
            std::io::Write::write_all(&mut writer, original).unwrap();
        }

        let decompressed = decompress_certificate(2, &compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn brotli_decompress_size_mismatch_fails() {
        let original = b"small data";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
            std::io::Write::write_all(&mut writer, original).unwrap();
        }

        // Claim a different uncompressed size
        let result = decompress_certificate(2, &compressed, 9999);
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_compression_algorithm_fails() {
        let result = decompress_certificate(99, &[0x00], 1);
        assert!(result.is_err());
    }

    #[test]
    fn corrupt_brotli_data_fails() {
        let result = decompress_certificate(2, &[0xFF, 0xFF, 0xFF], 10);
        assert!(result.is_err());
    }

    // ====================================================================
    // parse_certificate_message — edge cases
    // ====================================================================

    #[test]
    fn empty_certificate_message_fails() {
        let result = parse_certificate_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn single_cert_chain() {
        let cert = vec![0x30, 0x82, 0x03, 0xAA]; // fake DER

        let mut payload = Vec::new();
        payload.push(0); // empty context
        let list_start = payload.len();
        payload.extend_from_slice(&[0, 0, 0]); // placeholder

        let cert_len = cert.len() as u32;
        payload.push((cert_len >> 16) as u8);
        payload.push((cert_len >> 8) as u8);
        payload.push(cert_len as u8);
        payload.extend_from_slice(&cert);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        let list_len = payload.len() - list_start - 3;
        payload[list_start] = (list_len >> 16) as u8;
        payload[list_start + 1] = (list_len >> 8) as u8;
        payload[list_start + 2] = list_len as u8;

        let certs = parse_certificate_message(&payload).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    // ====================================================================
    // TranscriptHash — SHA-384 variant
    // ====================================================================

    #[test]
    fn transcript_hash_sha384() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha384);
        th.update(b"data");
        let hash = th.current_hash();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn transcript_hash_deterministic() {
        let mut th1 = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th1.update(b"same data");
        let mut th2 = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th2.update(b"same data");
        assert_eq!(th1.current_hash(), th2.current_hash());
    }

    // ====================================================================
    // compute_finished_verify_data — different hash sizes
    // ====================================================================

    #[test]
    fn finished_verify_data_sha384_produces_48_bytes() {
        let secret = [0x11u8; 48];
        let hash = [0x22u8; 48];
        let vd = compute_finished_verify_data(HkdfAlgorithm::Sha384, &secret, &hash).unwrap();
        assert_eq!(vd.len(), 48);
    }

    #[test]
    fn finished_verify_data_changes_with_different_transcript() {
        let secret = [0x42u8; 32];
        let vd1 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &[0xAA; 32]).unwrap();
        let vd2 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &[0xBB; 32]).unwrap();
        assert_ne!(vd1, vd2);
    }
}
