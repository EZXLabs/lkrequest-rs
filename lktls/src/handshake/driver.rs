//! High-level Sans-I/O handshake driver.
//!
//! [`HandshakeDriver`] orchestrates the full TLS handshake (1.3 or 1.2)
//! without any I/O dependency.  The caller feeds raw bytes from the
//! transport and receives byte buffers to send back.
//!
//! This eliminates the 500+ line async state machine that was previously
//! inlined in the I/O adapter layer.

use std::sync::Arc;

use crate::crypto::aead::{Aead, AeadAlgorithm};
use crate::crypto::hkdf::HkdfAlgorithm;
use crate::crypto::to_hex;
use crate::error::{AlertDescription, AlertLevel, Result, TlsError};
use crate::extensions::quic_transport_params::QuicTransportParams;
use crate::handshake::content_type;
use crate::handshake::server_hello::{check_downgrade_sentinel, detect_version_for_style};
use crate::handshake::tls12::{Tls12Handshake, Tls12HandshakeAction, Tls12State, Tls12TrafficKeys};
use crate::handshake::tls13::{
    client_hello_extensions, HandshakeAction, HandshakeComplete, HandshakeKeys, Tls13Handshake,
    TrafficSecrets,
};
use crate::profile::types::TlsProfile;
use crate::record::reader::RecordReader;
use crate::record::writer::RecordWriter;
use crate::session_store::{AlpsSessionState, SessionStore, TicketTlsVersion};
use crate::verify::policy::VerificationPolicy;
use crate::{ClientHelloCallback, KeyLogCallback};

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Output produced by [`HandshakeDriver::progress`].
pub enum HandshakeOutput {
    /// Send these bytes to the remote peer, then call `progress()` again.
    SendData(Vec<u8>),
    /// Need more data from the transport. Call `feed()` then `progress()`.
    NeedData,
    /// Handshake complete. Contains final bytes to send (may be empty)
    /// and the handshake result.
    Done {
        /// Final bytes to send to the peer (client Finished, etc.).
        /// May be empty if everything was already sent.
        to_send: Vec<u8>,
        /// The completed handshake result (boxed to reduce enum size).
        result: Box<HandshakeResult>,
    },
}

/// Result of a completed TLS handshake.
pub struct HandshakeResult {
    /// Record reader with application traffic keys installed.
    pub reader: RecordReader,
    /// Record writer with application traffic keys installed.
    pub writer: RecordWriter,
    /// Negotiated ALPN protocol (if any).
    pub negotiated_alpn: Option<String>,
    /// Negotiated cipher suite (if available).
    pub negotiated_cipher_suite: Option<u16>,
    /// Negotiated TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    pub negotiated_version: Option<u16>,
    /// Server certificate chain (DER, leaf first); empty on resumption.
    pub peer_certificates: Vec<Vec<u8>>,
    /// Post-handshake state for processing KeyUpdate messages (TLS 1.3 only).
    pub post_handshake: Option<PostHandshakeState>,
    /// Session ticket context for processing NewSessionTicket messages.
    pub session_ticket_ctx: Option<SessionTicketContext>,
}

/// Output produced by [`QuicHandshakeDriver::progress`].
pub enum QuicHandshakeOutput {
    /// Raw handshake bytes to send in QUIC CRYPTO frames.
    SendData(Vec<u8>),
    /// Need more decrypted CRYPTO stream bytes.
    NeedData,
    /// Handshake traffic secrets are ready after ServerHello.
    HandshakeSecretsReady {
        to_send: Vec<u8>,
        secrets: QuicTrafficSecrets,
    },
    /// Handshake complete.
    Done {
        to_send: Vec<u8>,
        result: Box<QuicHandshakeResult>,
    },
}

/// QUIC-specific handshake result.
pub struct QuicHandshakeResult {
    pub negotiated_alpn: Option<String>,
    pub negotiated_cipher_suite: Option<u16>,
    pub handshake_secrets: QuicTrafficSecrets,
    pub app_secrets: QuicTrafficSecrets,
    pub post_handshake: Option<PostHandshakeState>,
    pub session_ticket_ctx: Option<SessionTicketContext>,
    pub peer_transport_params: Option<QuicTransportParams>,
    pub early_data_accepted: bool,
    /// Whether the verified TLS handshake selected an offered resumption PSK.
    pub session_resumed: bool,
}

/// QUIC traffic secrets with the metadata needed for packet key derivation.
#[derive(Debug, Clone)]
pub struct QuicTrafficSecrets {
    pub client_secret: Vec<u8>,
    pub server_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
}

/// State needed to process TLS 1.3 KeyUpdate messages after the handshake.
pub struct PostHandshakeState {
    pub server_app_secret: Vec<u8>,
    pub client_app_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
    /// Exporter master secret (RFC 8446 §7.5), backing `export_keying_material`.
    pub exporter_master_secret: Vec<u8>,
}

/// Context needed to process NewSessionTicket messages after the handshake.
pub struct SessionTicketContext {
    pub resumption_master_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
    pub alps: AlpsSessionState,
    pub peer_transport_parameters: Option<Vec<u8>>,
    pub store: Arc<dyn SessionStore>,
    pub host_key: String,
}

impl SessionTicketContext {
    /// Parse and store a post-handshake NewSessionTicket message.
    pub fn process_new_session_ticket(&self, payload: &[u8]) {
        match crate::session_store::parse_tls13_new_session_ticket(
            payload,
            &self.resumption_master_secret,
            self.hkdf_algorithm,
            self.aead_algorithm,
            self.cipher_suite,
            self.alpn.clone(),
        ) {
            Ok(mut ticket_data) => {
                ticket_data.alps = self.alps.clone();
                ticket_data.peer_transport_parameters = self.peer_transport_parameters.clone();
                self.store.store(&self.host_key, ticket_data);
                tracing::debug!(host = %self.host_key, "tls.session_ticket_stored");
            }
            Err(e) => {
                tracing::warn!(error = %e, "tls.session_ticket_parse_failed");
            }
        }
    }
}

impl PostHandshakeState {
    /// Process a TLS 1.3 KeyUpdate message and return the new AEAD
    /// to install on the record reader.
    pub fn process_key_update(&mut self) -> Result<Aead> {
        use crate::crypto::hkdf::hkdf_expand_label;

        let hash_len = self.hkdf_algorithm.hash_len();
        let new_secret = hkdf_expand_label(
            self.hkdf_algorithm,
            &self.server_app_secret,
            "traffic upd",
            &[],
            hash_len,
        )?;

        let new_key = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "key",
            &[],
            self.aead_algorithm.key_len(),
        )?;

        let new_iv = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "iv",
            &[],
            self.aead_algorithm.nonce_len(),
        )?;

        let new_aead = Aead::new(self.aead_algorithm, &new_key, &new_iv)?;
        self.server_app_secret = new_secret;

        tracing::debug!("tls.key_update_processed");
        Ok(new_aead)
    }

    /// Build a KeyUpdate response message and derive a new client (write-side)
    /// AEAD.  Called when the server sends KeyUpdate with `update_requested`.
    ///
    /// Returns `(key_update_message, new_write_aead)`:
    /// - `key_update_message`: the handshake message bytes (type 0x18 + body)
    ///   that the caller must send encrypted with the **current** write key.
    /// - `new_write_aead`: the new AEAD to install on the record writer
    ///   **after** the message has been encrypted.
    pub fn build_key_update_response(&mut self) -> Result<(Vec<u8>, Aead)> {
        use crate::crypto::hkdf::hkdf_expand_label;

        let hash_len = self.hkdf_algorithm.hash_len();
        let new_secret = hkdf_expand_label(
            self.hkdf_algorithm,
            &self.client_app_secret,
            "traffic upd",
            &[],
            hash_len,
        )?;

        let new_key = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "key",
            &[],
            self.aead_algorithm.key_len(),
        )?;

        let new_iv = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "iv",
            &[],
            self.aead_algorithm.nonce_len(),
        )?;

        let new_aead = Aead::new(self.aead_algorithm, &new_key, &new_iv)?;
        self.client_app_secret = new_secret;

        // Build KeyUpdate handshake message:
        //   msg_type = 0x18, length = 1, update_not_requested = 0x00
        let msg = vec![0x18, 0x00, 0x00, 0x01, 0x00];

        tracing::debug!("tls.key_update_response_built");
        Ok((msg, new_aead))
    }
}

// ---------------------------------------------------------------------------
// HandshakeConfig
// ---------------------------------------------------------------------------

/// Configuration for the handshake driver.
#[derive(Clone)]
pub struct HandshakeConfig {
    pub profile: TlsProfile,
    pub hostname: String,
    pub port: u16,
    pub verification_policy: VerificationPolicy,
    pub alps_payload: Option<Vec<u8>>,
    pub session_store: Option<Arc<dyn SessionStore>>,
    pub ech_config_list: Option<Vec<u8>>,
    pub custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,
    pub keylog_callback: Option<KeyLogCallback>,
    /// Observes the raw ClientHello bytes about to be sent (see
    /// [`ClientHelloCallback`]). Does not affect the handshake.
    pub client_hello_callback: Option<ClientHelloCallback>,
}

/// QUIC handshake configuration wrapper.
#[derive(Clone)]
pub struct QuicHandshakeConfig {
    pub tls: HandshakeConfig,
    pub transport_parameters: Vec<u8>,
}

impl HandshakeConfig {
    pub fn into_quic(self, transport_parameters: Vec<u8>) -> QuicHandshakeConfig {
        QuicHandshakeConfig {
            tls: self,
            transport_parameters,
        }
    }
}

// ---------------------------------------------------------------------------
// DriverState
// ---------------------------------------------------------------------------

enum DriverState {
    Start,
    WaitServerHello {
        handshake: Tls13Handshake,
        ch_msg: Vec<u8>,
    },
    Tls13Encrypted {
        handshake: Tls13Handshake,
    },
    Tls12ServerFlight {
        handshake: Tls12Handshake,
        client_random: [u8; 32],
    },
    Tls12WaitServerFinished {
        handshake: Tls12Handshake,
        client_random: [u8; 32],
        traffic_keys: Tls12TrafficKeys,
        server_ccs_received: bool,
    },
    Complete,
}

enum QuicDriverState {
    Start,
    WaitServerHello { handshake: Tls13Handshake },
    Tls13Encrypted { handshake: Tls13Handshake },
    Complete,
}

// ---------------------------------------------------------------------------
// HandshakeDriver
// ---------------------------------------------------------------------------

/// Sans-I/O TLS handshake driver.
///
/// Orchestrates the full TLS 1.3 or 1.2 handshake. Usage:
///
/// 1. Call [`start()`](Self::start) → send the returned bytes.
/// 2. Read from transport → [`feed()`](Self::feed).
/// 3. Call [`progress()`](Self::progress) in a loop:
///    - `SendData(bytes)` → send bytes, then call `progress()` again.
///    - `NeedData` → read more, `feed()`, then `progress()`.
///    - `Done { to_send, result }` → send `to_send`, use `result`.
pub struct HandshakeDriver {
    config: HandshakeConfig,
    state: DriverState,
    reader: RecordReader,
    writer: RecordWriter,
    /// Reassembly buffer for the TLS 1.3 encrypted handshake flight.
    ///
    /// A handshake message MAY be fragmented across several records (RFC 8446
    /// §5.1: "Handshake messages MAY be … fragmented across several records"),
    /// and server Certificate flights routinely are. Decrypted handshake bytes
    /// are appended here and only *complete* messages are handed to the state
    /// machine, with any partial trailer carried to the next record — the same
    /// buffering the QUIC CRYPTO path already does, and what BoringSSL does with
    /// its handshake buffer (`ssl3_read_handshake_bytes`).
    hs_buffer: Vec<u8>,
    /// Original session ticket taken from the store during `start()`.
    /// Preserved so that if the server negotiates TLS 1.2 instead of 1.3,
    /// the ticket can be used for TLS 1.2 session resumption.
    original_ticket: Option<crate::session_store::SessionTicketData>,
    /// A real ECH offer was rejected by selection of TLS 1.2. The outer
    /// handshake authenticates only the public name and cannot yield traffic.
    tls12_ech_rejected: bool,
    /// Failure flight generated for a local protocol error, including any
    /// browser-specific compatibility CCS before the fatal alert.
    ///
    /// The Sans-I/O API returns the original error to the caller, so the alert
    /// is retained separately for the transport adapter to send best-effort.
    pending_alert: Option<Vec<u8>>,
    /// Plaintext compatibility CCS queued for the browser's client flight.
    pending_tls13_ccs: Vec<u8>,
    /// Version parsing failed before a browser selected its record version.
    initial_alert_version: bool,
}

impl HandshakeDriver {
    pub fn new(config: HandshakeConfig) -> Self {
        let mut reader = RecordReader::new();
        // RFC 8449 §4: the `record_size_limit` this profile puts in the
        // ClientHello bounds the records the *peer* may send us, and "an
        // endpoint that receives a record larger than its advertised limit MUST
        // generate a fatal 'record_overflow' alert". Arm the reader here: the
        // extension goes out in the first flight, so the limit is in force from
        // the first protected record the server sends. Mirrors
        // `writer.set_peer_record_size_limit()` on the send side, which is fed
        // from the server's extension instead.
        reader.set_own_record_size_limit(config.profile.record_size_limit);
        reader.set_client_style(config.profile.tls_client_hello_style);
        Self {
            config,
            state: DriverState::Start,
            reader,
            writer: RecordWriter::new(),
            hs_buffer: Vec::new(),
            original_ticket: None,
            tls12_ech_rejected: false,
            pending_alert: None,
            pending_tls13_ccs: Vec::new(),
            initial_alert_version: false,
        }
    }

    /// Build and return the initial ClientHello record bytes.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let host_key = format!("{}:{}", self.config.hostname, self.config.port);

        let mut hs = Tls13Handshake::new(self.config.profile.clone(), &self.config.hostname);
        hs.set_verification_policy(self.config.verification_policy);
        if let Some(ref a) = self.config.custom_ca_anchors {
            hs.set_custom_ca_anchors(Arc::clone(a));
        }
        if let Some(ref p) = self.config.alps_payload {
            hs.set_alps_payload(p.clone());
        }
        if let Some(ref e) = self.config.ech_config_list {
            hs.set_ech_config(e.clone());
        }
        if let Some(ref cb) = self.config.keylog_callback {
            hs.set_keylog_callback(Arc::clone(cb));
        }
        let resumption_cfg = &self.config.profile.session_resumption;
        if resumption_cfg.any_enabled() {
            if let Some(ref store) = self.config.session_store {
                if let Some(ticket) = store.take(&host_key) {
                    tracing::debug!(
                        host = %self.config.hostname,
                        ticket_len = ticket.ticket.len(),
                        tls_version = ?ticket.tls_version,
                        "tls.attempting_session_resumption",
                    );
                    match ticket.tls_version {
                        TicketTlsVersion::Tls13 if resumption_cfg.tls13_psk => {
                            let alpn_compatible =
                                match (&ticket.alpn, &self.config.profile.alpn_protocols) {
                                    (None, _) => true,
                                    (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => {
                                        true
                                    }
                                    _ => false,
                                };
                            if alpn_compatible {
                                self.original_ticket = Some(ticket.clone());
                                hs.set_psk_ticket(ticket);
                            } else {
                                tracing::debug!(
                                    host = %self.config.hostname,
                                    ticket_alpn = ?ticket.alpn,
                                    "tls.psk_ticket_alpn_mismatch — skipping resumption",
                                );
                            }
                        }
                        TicketTlsVersion::Tls12
                            if resumption_cfg.tls12_session_ticket
                                && self.config.ech_config_list.is_none() =>
                        {
                            let alpn_compatible =
                                match (&ticket.alpn, &self.config.profile.alpn_protocols) {
                                    (None, _) => true,
                                    (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => {
                                        true
                                    }
                                    _ => false,
                                };
                            if alpn_compatible {
                                self.original_ticket = Some(ticket.clone());
                                hs.set_tls12_session_ticket(ticket.ticket.clone());
                            } else {
                                tracing::debug!(
                                    host = %self.config.hostname,
                                    ticket_alpn = ?ticket.alpn,
                                    "tls12.session_ticket_alpn_mismatch — skipping resumption",
                                );
                            }
                        }
                        _ => {
                            tracing::debug!(
                                host = %self.config.hostname,
                                tls_version = ?ticket.tls_version,
                                "tls.session_resumption_disabled_for_version",
                            );
                        }
                    }
                }
            }
        }

        let ch_msg = hs.build_client_hello()?;
        // Observe the exact ClientHello handshake message (0x01-prefixed, before
        // TLS-record framing) the moment it is produced. Honoured here so the hook
        // works for direct lktls users too, not just lkrequest's connector.
        if let Some(ref cb) = self.config.client_hello_callback {
            cb(&ch_msg);
        }
        let ch_record = self.writer.write_record(content_type::HANDSHAKE, &ch_msg)?;
        tracing::debug!("tls.client_hello_sent");

        self.state = DriverState::WaitServerHello {
            handshake: hs,
            ch_msg,
        };
        Ok(ch_record)
    }

    /// Feed raw bytes received from the transport.
    pub fn feed(&mut self, data: &[u8]) {
        self.reader.feed(data);
    }

    /// Drive the handshake forward. Call in a loop after each `feed()`.
    pub fn progress(&mut self) -> Result<HandshakeOutput> {
        match self.progress_inner() {
            Ok(output) => Ok(output),
            Err(error) => {
                let ccs = std::mem::take(&mut self.pending_tls13_ccs);
                if self.config.profile.tls_client_hello_style
                    == crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                    && !matches!(&error, TlsError::Alert(_))
                    && !ccs.is_empty()
                {
                    self.pending_alert.get_or_insert_with(Vec::new).extend(ccs);
                }
                if let TlsError::LocalAlert { alert, .. } = &error {
                    let bytes = [alert.level.as_byte(), alert.description.as_byte()];
                    let encoded = if std::mem::take(&mut self.initial_alert_version) {
                        RecordWriter::new().write_record(content_type::ALERT, &bytes)
                    } else {
                        self.writer.write_record(content_type::ALERT, &bytes)
                    };
                    match encoded {
                        Ok(record) => self
                            .pending_alert
                            .get_or_insert_with(Vec::new)
                            .extend(record),
                        Err(record_error) => tracing::warn!(
                            error = %record_error,
                            "tls.local_alert_record_failed"
                        ),
                    }
                }
                Err(error)
            }
        }
    }

    /// Take a locally generated failure flight after [`Self::progress`]
    /// returns [`TlsError::LocalAlert`].
    pub fn take_pending_alert(&mut self) -> Option<Vec<u8>> {
        self.pending_alert.take()
    }

    fn progress_inner(&mut self) -> Result<HandshakeOutput> {
        // TLS 1.2 WaitServerFinished has special record-level handling
        if matches!(self.state, DriverState::Tls12WaitServerFinished { .. }) {
            return self.progress_tls12_wait_finished();
        }

        loop {
            let record = match self.reader.next_record() {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(HandshakeOutput::NeedData),
                Err(error) => {
                    self.initial_alert_version = matches!(&self.state,
                        DriverState::WaitServerHello { handshake, .. } if !handshake.has_received_hrr())
                        && matches!(
                            self.config.profile.tls_client_hello_style,
                            crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                                | crate::profile::types::TlsClientHelloStyle::FirefoxNss
                        );
                    return Err(error);
                }
            };

            if record.content_type == content_type::CHANGE_CIPHER_SPEC {
                if let DriverState::WaitServerHello { handshake, .. } = &self.state {
                    let style = self.config.profile.tls_client_hello_style;
                    let after_hrr = handshake.has_received_hrr();
                    let browser_style = matches!(
                        style,
                        crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                            | crate::profile::types::TlsClientHelloStyle::FirefoxNss
                    );
                    if record.payload != [1] || (!after_hrr && browser_style) {
                        self.initial_alert_version = !after_hrr && browser_style;
                        return Err(TlsError::local_alert(
                            if record.payload == [1] {
                                AlertDescription::UnexpectedMessage
                            } else if style
                                == crate::profile::types::TlsClientHelloStyle::FirefoxNss
                            {
                                if after_hrr && record.payload.len() != 1 {
                                    AlertDescription::DecodeError
                                } else {
                                    AlertDescription::IllegalParameter
                                }
                            } else {
                                AlertDescription::UnexpectedMessage
                            },
                            "unexpected ChangeCipherSpec before ServerHello",
                        ));
                    }
                }
                if let DriverState::Tls12ServerFlight { ref handshake, .. } = self.state {
                    if handshake.state() == Tls12State::WaitCertificateOrAbbreviated {
                        return self.handle_tls12_abbreviated_ccs();
                    }
                }
                continue;
            }

            if record.content_type == content_type::ALERT {
                let level = record.payload.first().copied().unwrap_or(0);
                let desc = record.payload.get(1).copied().unwrap_or(0);
                return Err(TlsError::Alert(crate::error::TlsAlert::from_bytes(
                    level, desc,
                )));
            }

            if record.content_type != content_type::HANDSHAKE {
                return Err(TlsError::UnexpectedMessage(format!(
                    "expected handshake, got content_type=0x{:02x}",
                    record.content_type
                )));
            }

            let state = std::mem::replace(&mut self.state, DriverState::Complete);
            match state {
                DriverState::WaitServerHello { handshake, ch_msg } => {
                    if handshake.has_received_hrr() {
                        return self.begin_tls13(handshake, &record.payload);
                    }
                    let style = self.config.profile.tls_client_hello_style;
                    let (version, version_extension) =
                        match detect_version_for_style(&record.payload, style, false) {
                            Ok(selected) => selected,
                            Err(error) => {
                                self.initial_alert_version =
                                    matches!(style,
                                crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                                | crate::profile::types::TlsClientHelloStyle::FirefoxNss);
                                return Err(error);
                            }
                        };
                    if version < self.config.profile.tls_min_version.as_u16()
                        || version > self.config.profile.tls_max_version.as_u16()
                    {
                        return Err(TlsError::local_alert(
                            AlertDescription::ProtocolVersion,
                            "server selected a TLS version outside configured bounds",
                        ));
                    }
                    let offered = client_hello_extensions(&ch_msg).ok_or_else(|| {
                        TlsError::InvalidProfile("cannot parse ClientHello version offer".into())
                    })?;
                    let version_offered = match offered.iter().find(|(kind, _)| *kind == 43) {
                        Some((_, payload)) => {
                            crate::extensions::supported_versions::parse_client_versions(payload)
                                .is_some_and(|versions| versions.contains(&version))
                        }
                        None => version <= u16::from_be_bytes([ch_msg[4], ch_msg[5]]),
                    };
                    if !version_offered {
                        return Err(TlsError::local_alert(AlertDescription::ProtocolVersion, "server selected a TLS version absent from the actual ClientHello offer"));
                    }
                    if version_extension && version < 0x0304 {
                        return Err(TlsError::local_alert(
                            AlertDescription::UnsupportedExtension,
                            "supported_versions is not allowed in a TLS 1.2 ServerHello",
                        ));
                    }
                    tracing::debug!(
                        version = format_args!("0x{:04x}", version),
                        "tls.version_negotiated"
                    );

                    if version == 0x0304 {
                        return self.begin_tls13(handshake, &record.payload);
                    } else if version == 0x0303 {
                        let public_name = handshake.ech_rejection_public_name();
                        match self.begin_tls12(ch_msg, &record.payload, public_name)? {
                            HandshakeOutput::NeedData => continue,
                            other => return Ok(other),
                        }
                    } else {
                        return Err(TlsError::HandshakeFailure(format!(
                            "unsupported TLS version: 0x{version:04x}"
                        )));
                    }
                }
                DriverState::Tls13Encrypted { mut handshake } => {
                    // A handshake message may span several records (RFC 8446
                    // §5.1); large Certificate flights (e.g. Facebook) routinely
                    // do. Accumulate decrypted handshake bytes and process only
                    // complete messages, carrying any partial trailer to the
                    // next record. Multiple coalesced messages in one record are
                    // handled the same way.
                    self.hs_buffer.extend_from_slice(&record.payload);
                    let Some(messages) = take_complete_handshake_messages(&mut self.hs_buffer)?
                    else {
                        // No complete message yet — wait for the next record.
                        self.state = DriverState::Tls13Encrypted { handshake };
                        continue;
                    };
                    match handshake.process_handshake_record(&messages)? {
                        HandshakeAction::ContinueReading => {
                            self.state = DriverState::Tls13Encrypted { handshake };
                            continue;
                        }
                        HandshakeAction::Complete(c) => return self.finish_tls13(*c),
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected action during encrypted handshake".into(),
                            ));
                        }
                    }
                }
                DriverState::Tls12ServerFlight {
                    mut handshake,
                    client_random,
                } => {
                    // TLS 1.2 handshake messages (esp. a large Certificate) can
                    // also span several records (RFC 8446 §5.1 applies to 1.2's
                    // record layer too) — buffer and process only complete
                    // messages, mirroring the TLS 1.3 path above.
                    self.hs_buffer.extend_from_slice(&record.payload);
                    let Some(messages) = take_complete_handshake_messages(&mut self.hs_buffer)?
                    else {
                        self.state = DriverState::Tls12ServerFlight {
                            handshake,
                            client_random,
                        };
                        continue;
                    };
                    let action = handshake.process_handshake_record(&messages)?;
                    match action {
                        Tls12HandshakeAction::ContinueReading => {
                            self.state = DriverState::Tls12ServerFlight {
                                handshake,
                                client_random,
                            };
                            continue;
                        }
                        Tls12HandshakeAction::SendClientFlight(flight) => {
                            return self.finish_tls12_full(handshake, client_random, flight);
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected TLS 1.2 action during server flight".into(),
                            ));
                        }
                    }
                }
                DriverState::Start => {
                    return Err(TlsError::HandshakeFailure("start() not called".into()));
                }
                DriverState::Complete => {
                    return Err(TlsError::HandshakeFailure(
                        "handshake already complete".into(),
                    ));
                }
                DriverState::Tls12WaitServerFinished { .. } => unreachable!(),
            }
        }
    }

    // -----------------------------------------------------------------------
    // TLS 1.3
    // -----------------------------------------------------------------------

    fn begin_tls13(
        &mut self,
        mut handshake: Tls13Handshake,
        server_hello: &[u8],
    ) -> Result<HandshakeOutput> {
        let ccs_before_failure = self.config.profile.tls_client_hello_style
            == crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
            && !handshake.has_received_hrr()
            && crate::handshake::server_hello::tls13_failure_ccs_eligible(server_hello);
        let result = handshake.process_handshake_record(server_hello);
        if ccs_before_failure && matches!(&result, Err(TlsError::LocalAlert { .. })) {
            self.pending_alert = Some(
                self.writer
                    .write_record(content_type::CHANGE_CIPHER_SPEC, &[1])?,
            );
        }
        let action = result?;
        match action {
            HandshakeAction::InstallHandshakeKeys(keys) => {
                let mut ccs = if handshake.has_received_hrr() {
                    Vec::new()
                } else {
                    self.writer
                        .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?
                };
                if matches!(
                    self.config.profile.tls_client_hello_style,
                    crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl
                        | crate::profile::types::TlsClientHelloStyle::FirefoxNss
                ) {
                    self.pending_tls13_ccs = std::mem::take(&mut ccs);
                }
                self.reader.set_keys(Aead::new(
                    keys.aead_algorithm,
                    &keys.server_key,
                    &keys.server_iv,
                )?);
                self.writer.set_keys(Aead::new(
                    keys.aead_algorithm,
                    &keys.client_key,
                    &keys.client_iv,
                )?);
                self.state = DriverState::Tls13Encrypted { handshake };
                Ok(HandshakeOutput::SendData(ccs))
            }
            HandshakeAction::RetryClientHello(ch2) => {
                self.reader.select_tls13();
                let ccs = self
                    .writer
                    .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
                let mut rw = RecordWriter::new();
                rw.mark_post_initial();
                let ch2_record = rw.write_record(content_type::HANDSHAKE, &ch2)?;

                let mut buf = ccs;
                buf.extend_from_slice(&ch2_record);

                self.state = DriverState::WaitServerHello {
                    handshake,
                    ch_msg: ch2,
                };
                Ok(HandshakeOutput::SendData(buf))
            }
            _ => Err(TlsError::HandshakeFailure(
                "unexpected action after ServerHello".into(),
            )),
        }
    }

    fn finish_tls13(&mut self, complete: HandshakeComplete) -> Result<HandshakeOutput> {
        let mut send_buf = std::mem::take(&mut self.pending_tls13_ccs);

        if let Some(ref early) = complete.client_end_of_early_data {
            let mut early_writer = RecordWriter::new();
            early_writer.set_keys(Aead::new(
                early.aead_algorithm,
                &early.client_key,
                &early.client_iv,
            )?);
            send_buf.extend_from_slice(
                &early_writer.write_record(content_type::HANDSHAKE, &early.message)?,
            );
        }
        if let Some(ref cee) = complete.client_encrypted_extensions {
            send_buf.extend_from_slice(&self.writer.write_record(content_type::HANDSHAKE, cee)?);
        }
        if let Some(ref certificate) = complete.client_certificate {
            send_buf.extend_from_slice(
                &self
                    .writer
                    .write_record(content_type::HANDSHAKE, certificate)?,
            );
        }
        send_buf.extend_from_slice(
            &self
                .writer
                .write_record(content_type::HANDSHAKE, &complete.client_finished)?,
        );

        // ECH offered but not accepted: the outer handshake exists only to
        // authenticate the `public_name` (already done during certificate
        // verification) and to collect `retry_configs`. RFC 9849 §6.1.6 forbids
        // carrying application data on it — the true server name was never
        // protected — so finish the flight, send `ech_required`, and abort.
        //
        // Deliberately before installing application keys and before building
        // the session-ticket context: no traffic keys are handed out, and no
        // ticket from this connection may be cached, since it is bound to the
        // public_name identity rather than the one the caller asked for.
        if complete.ech_offered && !complete.ech_accepted {
            tracing::warn!(
                host = %self.config.hostname,
                retry_configs = complete.ech_retry_configs.as_ref().map_or(0, |c| c.len()),
                "tls.ech_rejected — aborting with ech_required",
            );
            // Finished closes the handshake-key epoch. Encode the following
            // alert at application sequence zero without exposing a connection
            // or creating a ticket context for the rejected outer handshake.
            let secrets = &complete.traffic_secrets;
            let mut alert_writer = RecordWriter::new();
            alert_writer.set_keys(Aead::new(
                secrets.aead_algorithm,
                &secrets.client_key,
                &secrets.client_iv,
            )?);
            let alert_record = alert_writer.write_record(
                content_type::ALERT,
                &[
                    AlertLevel::Fatal.as_byte(),
                    AlertDescription::EchRequired.as_byte(),
                ],
            )?;
            send_buf.extend_from_slice(&alert_record);
            self.pending_alert = Some(send_buf);
            return Err(TlsError::EchRejected {
                retry_configs: complete.ech_retry_configs.clone(),
            });
        }

        let ts = &complete.traffic_secrets;
        self.reader
            .set_keys(Aead::new(ts.aead_algorithm, &ts.server_key, &ts.server_iv)?);
        self.reader.finish_tls13_handshake();
        self.writer
            .set_keys(Aead::new(ts.aead_algorithm, &ts.client_key, &ts.client_iv)?);
        // RFC 8449: the server's `record_size_limit` from EncryptedExtensions
        // bounds the application records we send. Installed after the client
        // flight above so the handshake records stay byte-identical.
        self.writer
            .set_peer_record_size_limit(complete.peer_record_size_limit);
        if let Some(limit) = complete.peer_record_size_limit {
            tracing::debug!(limit, "tls.honouring_peer_record_size_limit");
        }

        if complete.ech_accepted {
            tracing::info!(host = %self.config.hostname, "tls.ech_accepted");
        }
        if let Some(ref rc) = complete.ech_retry_configs {
            tracing::info!(host = %self.config.hostname, len = rc.len(), "tls.ech_retry_configs_received");
        }
        tracing::debug!(
            version = "TLS1.3",
            alpn = ?complete.negotiated_alpn,
            aead = ?ts.aead_algorithm,
            ech_accepted = complete.ech_accepted,
            "tls.handshake_complete",
        );

        let host_key = format!("{}:{}", self.config.hostname, self.config.port);
        let st_ctx = if self.config.profile.session_resumption.store_tickets {
            self.config
                .session_store
                .as_ref()
                .map(|store| SessionTicketContext {
                    resumption_master_secret: complete.resumption_master_secret.clone(),
                    hkdf_algorithm: ts.hkdf_algorithm,
                    aead_algorithm: ts.aead_algorithm,
                    cipher_suite: complete.negotiated_cipher_suite,
                    alpn: complete.negotiated_alpn.clone(),
                    alps: complete.alps.clone(),
                    peer_transport_parameters: None,
                    store: Arc::clone(store),
                    host_key,
                })
        } else {
            None
        };

        self.state = DriverState::Complete;
        Ok(HandshakeOutput::Done {
            to_send: send_buf,
            result: Box::new(HandshakeResult {
                reader: std::mem::take(&mut self.reader),
                writer: std::mem::take(&mut self.writer),
                negotiated_alpn: complete.negotiated_alpn,
                negotiated_cipher_suite: Some(complete.negotiated_cipher_suite),
                negotiated_version: Some(0x0304),
                peer_certificates: complete.server_certificates,
                post_handshake: Some(PostHandshakeState {
                    server_app_secret: ts.server_app_secret.clone(),
                    client_app_secret: ts.client_app_secret.clone(),
                    hkdf_algorithm: ts.hkdf_algorithm,
                    aead_algorithm: ts.aead_algorithm,
                    exporter_master_secret: ts.exporter_master_secret.clone(),
                }),
                session_ticket_ctx: st_ctx,
            }),
        })
    }

    // -----------------------------------------------------------------------
    // TLS 1.2
    // -----------------------------------------------------------------------

    fn begin_tls12(
        &mut self,
        ch_msg: Vec<u8>,
        server_hello: &[u8],
        ech_public_name: Option<String>,
    ) -> Result<HandshakeOutput> {
        // RFC 8446 §4.1.3: only TLS 1.3-capable clients MUST check the
        // ServerHello.random downgrade sentinel. A client that explicitly
        // capped its `tls_max_version` at TLS 1.2 (e.g. Java SSLEngine,
        // Charles MITM) didn't advertise 1.3 in the first place, so the
        // server's sentinel is informational only and aborting on it would
        // wrongly reject every TLS 1.3-capable origin.
        if self.config.profile.tls_max_version.as_u16() >= 0x0304 {
            check_downgrade_sentinel(server_hello)?;
        }

        let client_random: [u8; 32] = ch_msg[4 + 2..4 + 2 + 32]
            .try_into()
            .map_err(|_| TlsError::HandshakeFailure("ClientHello too short".into()))?;

        self.tls12_ech_rejected = ech_public_name.is_some();
        if self.tls12_ech_rejected {
            self.original_ticket = None;
        }
        let mut tls12 = Tls12Handshake::new(
            client_random,
            ech_public_name.as_deref().unwrap_or(&self.config.hostname),
            self.config.verification_policy,
        );
        if let Some(ref a) = self.config.custom_ca_anchors {
            tls12.set_custom_ca_anchors(Arc::clone(a));
        }

        if let Some(ticket) = self.original_ticket.take() {
            if ticket.tls_version == TicketTlsVersion::Tls12 && !ticket.master_secret.is_empty() {
                tracing::debug!(host = %self.config.hostname, "tls12.attempting_session_ticket_resumption");
                // Carry the stored EMS flag so RFC 7627 §5.3 can be checked
                // once the server commits to resuming.
                tls12.set_session_ticket_resumption(
                    ticket.master_secret.clone(),
                    ticket.used_extended_master_secret,
                );
            }
        }

        tls12.feed_client_hello(&ch_msg);
        // The first server record may coalesce ServerHello with (part of) the
        // Certificate flight, and a handshake message may be fragmented across
        // records (RFC 8446 §5.1). Process the complete messages here and carry
        // any partial trailer into `hs_buffer` for the Tls12ServerFlight state.
        let mut initial = server_hello.to_vec();
        let action = match take_complete_handshake_messages(&mut initial)? {
            Some(msgs) => tls12.process_handshake_record(&msgs)?,
            None => Tls12HandshakeAction::ContinueReading,
        };
        self.hs_buffer = initial;
        match action {
            Tls12HandshakeAction::ContinueReading => {
                self.state = DriverState::Tls12ServerFlight {
                    handshake: tls12,
                    client_random,
                };
                Ok(HandshakeOutput::NeedData)
            }
            Tls12HandshakeAction::SendClientFlight(flight) => {
                self.finish_tls12_full(tls12, client_random, flight)
            }
            _ => {
                self.state = DriverState::Tls12ServerFlight {
                    handshake: tls12,
                    client_random,
                };
                Ok(HandshakeOutput::NeedData)
            }
        }
    }

    fn handle_tls12_abbreviated_ccs(&mut self) -> Result<HandshakeOutput> {
        let state = std::mem::replace(&mut self.state, DriverState::Complete);
        let (mut handshake, client_random) = match state {
            DriverState::Tls12ServerFlight {
                handshake,
                client_random,
            } => (handshake, client_random),
            _ => {
                return Err(TlsError::HandshakeFailure(
                    "unexpected state for abbreviated CCS".into(),
                ))
            }
        };

        let tk = handshake.accept_abbreviated_ccs()?;
        tk.install_on_reader(&mut self.reader)?;

        // Try to read server Finished from buffered data
        loop {
            match self.reader.next_record()? {
                Some(rec) if rec.content_type == content_type::CHANGE_CIPHER_SPEC => continue,
                Some(rec) if rec.content_type == content_type::HANDSHAKE => {
                    return self.complete_tls12_abbreviated(handshake, client_random, &rec.payload);
                }
                Some(rec) => {
                    return Err(TlsError::UnexpectedMessage(format!(
                        "expected server Finished, got 0x{:02x}",
                        rec.content_type
                    )));
                }
                None => {
                    // Need more data — transition to a waiting state.
                    // Re-use Tls12WaitServerFinished with a flag.
                    self.state = DriverState::Tls12WaitServerFinished {
                        handshake,
                        client_random,
                        traffic_keys: tk,
                        server_ccs_received: true,
                    };
                    return Ok(HandshakeOutput::NeedData);
                }
            }
        }
    }

    fn complete_tls12_abbreviated(
        &mut self,
        mut handshake: Tls12Handshake,
        client_random: [u8; 32],
        finished_payload: &[u8],
    ) -> Result<HandshakeOutput> {
        let abbr_flight = handshake.process_abbreviated_server_finished(finished_payload)?;

        let ccs = self
            .writer
            .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
        abbr_flight
            .traffic_keys
            .install_on_writer(&mut self.writer)?;
        // RFC 8449: honour the server's ServerHello `record_size_limit`.
        // Resumption renegotiates the limit, so it is read from this
        // handshake's ServerHello rather than carried over.
        self.writer
            .set_peer_record_size_limit(handshake.peer_record_size_limit());
        let fin = self
            .writer
            .write_record(content_type::HANDSHAKE, &abbr_flight.client_finished)?;

        let mut send_buf = Vec::with_capacity(ccs.len() + fin.len());
        send_buf.extend_from_slice(&ccs);
        send_buf.extend_from_slice(&fin);

        self.emit_tls12_keylog(&handshake, &client_random);

        let alpn = handshake.negotiated_alpn().map(|s| s.to_string());
        tracing::debug!(
            version = "TLS1.2", cipher = ?abbr_flight.traffic_keys.cipher_suite,
            alpn = ?alpn, abbreviated = true, "tls.handshake_complete",
        );

        self.state = DriverState::Complete;
        Ok(HandshakeOutput::Done {
            to_send: send_buf,
            result: Box::new(HandshakeResult {
                reader: std::mem::take(&mut self.reader),
                writer: std::mem::take(&mut self.writer),
                negotiated_alpn: alpn,
                negotiated_cipher_suite: Some(abbr_flight.traffic_keys.cipher_suite.code_point()),
                negotiated_version: Some(0x0303),
                peer_certificates: handshake.server_certificates().to_vec(),
                post_handshake: None,
                session_ticket_ctx: None,
            }),
        })
    }

    fn finish_tls12_full(
        &mut self,
        handshake: Tls12Handshake,
        client_random: [u8; 32],
        flight: crate::handshake::tls12::Tls12ClientFlight,
    ) -> Result<HandshakeOutput> {
        let certificate = match flight.client_certificate.as_deref() {
            Some(message) => self.writer.write_record(content_type::HANDSHAKE, message)?,
            None => Vec::new(),
        };
        let cke = self
            .writer
            .write_record(content_type::HANDSHAKE, &flight.client_key_exchange)?;
        let ccs = self
            .writer
            .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
        flight.traffic_keys.install_on_writer(&mut self.writer)?;
        // RFC 8449: honour the server's ServerHello `record_size_limit`.
        self.writer
            .set_peer_record_size_limit(handshake.peer_record_size_limit());
        let fin = self
            .writer
            .write_record(content_type::HANDSHAKE, &flight.client_finished)?;

        let mut send_buf =
            Vec::with_capacity(certificate.len() + cke.len() + ccs.len() + fin.len());
        send_buf.extend_from_slice(&certificate);
        send_buf.extend_from_slice(&cke);
        send_buf.extend_from_slice(&ccs);
        send_buf.extend_from_slice(&fin);

        self.state = DriverState::Tls12WaitServerFinished {
            handshake,
            client_random,
            traffic_keys: flight.traffic_keys,
            server_ccs_received: false,
        };

        Ok(HandshakeOutput::SendData(send_buf))
    }

    fn progress_tls12_wait_finished(&mut self) -> Result<HandshakeOutput> {
        loop {
            let record = match self.reader.next_record()? {
                Some(r) => r,
                None => return Ok(HandshakeOutput::NeedData),
            };

            if record.content_type == content_type::ALERT {
                let level = record.payload.first().copied().unwrap_or(0);
                let desc = record.payload.get(1).copied().unwrap_or(0);
                return Err(TlsError::Alert(crate::error::TlsAlert::from_bytes(
                    level, desc,
                )));
            }

            let server_ccs_received = match &self.state {
                DriverState::Tls12WaitServerFinished {
                    server_ccs_received,
                    ..
                } => *server_ccs_received,
                _ => return Err(TlsError::HandshakeFailure("unexpected state".into())),
            };

            if record.content_type == content_type::CHANGE_CIPHER_SPEC {
                if !server_ccs_received {
                    // Install read keys: need to take ownership of traffic_keys temporarily
                    // to call install_on_reader (which borrows &mut self.reader).
                    let state = std::mem::replace(&mut self.state, DriverState::Complete);
                    if let DriverState::Tls12WaitServerFinished {
                        handshake,
                        client_random,
                        traffic_keys,
                        ..
                    } = state
                    {
                        traffic_keys.install_on_reader(&mut self.reader)?;
                        self.state = DriverState::Tls12WaitServerFinished {
                            handshake,
                            client_random,
                            traffic_keys,
                            server_ccs_received: true,
                        };
                    }
                }
                continue;
            }

            if record.content_type == content_type::HANDSHAKE {
                let msg_type = record.payload.first().copied().unwrap_or(0);

                if !server_ccs_received {
                    // Pre-CCS handshake message (e.g. NewSessionTicket)
                    self.try_store_tls12_session_ticket(msg_type, &record.payload);

                    if let DriverState::Tls12WaitServerFinished {
                        ref mut handshake, ..
                    } = self.state
                    {
                        handshake.feed_handshake_message(&record.payload);
                    }
                    continue;
                }

                // Post-CCS: this should be server Finished
                let state = std::mem::replace(&mut self.state, DriverState::Complete);
                if let DriverState::Tls12WaitServerFinished {
                    mut handshake,
                    client_random,
                    traffic_keys,
                    ..
                } = state
                {
                    handshake.notify_server_ccs_received();
                    handshake.process_server_finished(&record.payload)?;

                    self.emit_tls12_keylog(&handshake, &client_random);

                    if self.tls12_ech_rejected {
                        // TLS 1.2 keeps the CCS-installed epoch after Finished.
                        // Send an encrypted fatal alert without returning keys.
                        self.pending_alert = Some(self.writer.write_record(
                            content_type::ALERT,
                            &[2, AlertDescription::EchRequired.as_byte()],
                        )?);
                        self.state = DriverState::Complete;
                        return Err(TlsError::EchRejected {
                            retry_configs: None,
                        });
                    }

                    let alpn = handshake.negotiated_alpn().map(|s| s.to_string());
                    tracing::debug!(
                        version = "TLS1.2", cipher = ?traffic_keys.cipher_suite,
                        alpn = ?alpn, "tls.handshake_complete",
                    );

                    self.state = DriverState::Complete;
                    return Ok(HandshakeOutput::Done {
                        to_send: Vec::new(),
                        result: Box::new(HandshakeResult {
                            reader: std::mem::take(&mut self.reader),
                            writer: std::mem::take(&mut self.writer),
                            negotiated_alpn: alpn,
                            negotiated_cipher_suite: Some(traffic_keys.cipher_suite.code_point()),
                            negotiated_version: Some(0x0303),
                            peer_certificates: handshake.server_certificates().to_vec(),
                            post_handshake: None,
                            session_ticket_ctx: None,
                        }),
                    });
                }
            }
        }
    }

    /// Try to parse and store a TLS 1.2 NewSessionTicket from a pre-CCS handshake message.
    fn try_store_tls12_session_ticket(&self, msg_type: u8, payload: &[u8]) {
        if self.tls12_ech_rejected {
            return;
        }
        if msg_type != 0x04 {
            return;
        }
        if !self.config.profile.session_resumption.store_tickets {
            return;
        }
        let DriverState::Tls12WaitServerFinished { ref handshake, .. } = self.state else {
            return;
        };
        let Some(ref store) = self.config.session_store else {
            return;
        };
        let Some(ms) = handshake.master_secret() else {
            return;
        };
        let host_key = format!("{}:{}", self.config.hostname, self.config.port);
        match crate::session_store::parse_tls12_new_session_ticket(
            payload,
            ms,
            handshake.negotiated_alpn().map(|s| s.to_string()),
            handshake.negotiated_cipher_suite(),
            // RFC 7627 §5.4: persist the EMS flag so §5.3 can be checked when
            // this ticket is later used to resume.
            Some(handshake.used_extended_master_secret()),
        ) {
            Ok(td) => {
                store.store(&host_key, td);
                tracing::debug!(host = %host_key, "tls12.session_ticket_stored");
            }
            Err(e) => {
                tracing::warn!(error = %e, "tls12.session_ticket_parse_failed");
            }
        }
    }

    fn emit_tls12_keylog(&self, handshake: &Tls12Handshake, client_random: &[u8; 32]) {
        if let Some(ref cb) = self.config.keylog_callback {
            if let Some(ms) = handshake.master_secret() {
                cb(&format!(
                    "CLIENT_RANDOM {} {}",
                    to_hex(client_random),
                    to_hex(ms)
                ));
            }
        }
    }
}

/// Sans-I/O QUIC-TLS handshake driver.
pub struct QuicHandshakeDriver {
    config: QuicHandshakeConfig,
    state: QuicDriverState,
    input: Vec<u8>,
    handshake_secrets: Option<QuicTrafficSecrets>,
}

impl QuicHandshakeDriver {
    pub fn new(config: QuicHandshakeConfig) -> Self {
        Self {
            config,
            state: QuicDriverState::Start,
            input: Vec::new(),
            handshake_secrets: None,
        }
    }

    pub fn start(&mut self) -> Result<Vec<u8>> {
        let host_key = format!("{}:{}", self.config.tls.hostname, self.config.tls.port);

        let mut hs =
            Tls13Handshake::new(self.config.tls.profile.clone(), &self.config.tls.hostname);
        hs.enable_quic_mode();
        hs.set_quic_transport_parameters(self.config.transport_parameters.clone());
        if let Some(ref p) = self.config.tls.alps_payload {
            hs.set_alps_payload(p.clone());
        }
        hs.set_verification_policy(self.config.tls.verification_policy);
        if let Some(ref anchors) = self.config.tls.custom_ca_anchors {
            hs.set_custom_ca_anchors(Arc::clone(anchors));
        }
        if let Some(ref ech) = self.config.tls.ech_config_list {
            hs.set_ech_config(ech.clone());
        }
        if let Some(ref cb) = self.config.tls.keylog_callback {
            hs.set_keylog_callback(Arc::clone(cb));
        }

        let resumption_cfg = &self.config.tls.profile.session_resumption;
        if resumption_cfg.tls13_psk {
            if let Some(ref store) = self.config.tls.session_store {
                if let Some(ticket) = store.take(&host_key) {
                    if ticket.tls_version == TicketTlsVersion::Tls13 {
                        let alpn_compatible =
                            match (&ticket.alpn, &self.config.tls.profile.alpn_protocols) {
                                (None, _) => true,
                                (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => true,
                                _ => false,
                            };
                        if alpn_compatible {
                            hs.set_psk_ticket(ticket);
                        }
                    }
                }
            }
        }

        let ch = hs.build_client_hello()?;
        // Same ClientHello observation hook as the TCP driver. QUIC has no TLS
        // record layer, so this is the bare handshake message (CRYPTO-frame
        // payload) — matching what the TCP driver emits to the callback.
        if let Some(ref cb) = self.config.tls.client_hello_callback {
            cb(&ch);
        }
        self.state = QuicDriverState::WaitServerHello { handshake: hs };
        Ok(ch)
    }

    /// Return the ticket and complete ClientHello used by an actual 0-RTT offer.
    ///
    /// Available after `start()` and before processing ServerHello or
    /// HelloRetryRequest. The serialized hello must contain an empty early_data
    /// extension and offer this ticket as its first PSK identity. With real ECH,
    /// the returned transcript is the reconstructed ClientHelloInner, including
    /// its binder, rather than the encrypted ClientHelloOuter sent on the wire.
    /// Callers must still enforce their transport-specific 0-RTT prerequisites.
    pub fn early_data_offer(&self) -> Option<(&crate::session_store::SessionTicketData, &[u8])> {
        match &self.state {
            QuicDriverState::WaitServerHello { handshake } => handshake.early_data_offer(),
            _ => None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    pub fn progress(&mut self) -> Result<QuicHandshakeOutput> {
        loop {
            let state = std::mem::replace(&mut self.state, QuicDriverState::Complete);
            match state {
                QuicDriverState::Start => {
                    return Err(TlsError::HandshakeFailure("start() not called".into()));
                }
                QuicDriverState::Complete => {
                    return Err(TlsError::HandshakeFailure(
                        "handshake already complete".into(),
                    ));
                }
                QuicDriverState::WaitServerHello { handshake } => {
                    let Some(server_hello) = take_next_handshake_message(&mut self.input)? else {
                        self.state = QuicDriverState::WaitServerHello { handshake };
                        return Ok(QuicHandshakeOutput::NeedData);
                    };

                    if handshake.has_received_hrr() {
                        return self.begin_quic_tls13(handshake, &server_hello);
                    }
                    let (version, _) = detect_version_for_style(
                        &server_hello,
                        self.config.tls.profile.tls_client_hello_style,
                        false,
                    )?;
                    if version != 0x0304 {
                        return Err(TlsError::local_alert(
                            AlertDescription::ProtocolVersion,
                            format!("QUIC requires TLS 1.3, got 0x{version:04x}"),
                        ));
                    }
                    return self.begin_quic_tls13(handshake, &server_hello);
                }
                QuicDriverState::Tls13Encrypted { mut handshake } => {
                    let Some(messages) = take_complete_handshake_messages(&mut self.input)? else {
                        self.state = QuicDriverState::Tls13Encrypted { handshake };
                        return Ok(QuicHandshakeOutput::NeedData);
                    };

                    match handshake.process_handshake_record(&messages)? {
                        HandshakeAction::ContinueReading => {
                            self.state = QuicDriverState::Tls13Encrypted { handshake };
                            continue;
                        }
                        HandshakeAction::Complete(complete) => {
                            return self.finish_quic_tls13(*complete);
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected action during QUIC encrypted handshake".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn begin_quic_tls13(
        &mut self,
        mut handshake: Tls13Handshake,
        server_hello: &[u8],
    ) -> Result<QuicHandshakeOutput> {
        match handshake.process_handshake_record(server_hello)? {
            HandshakeAction::InstallHandshakeKeys(keys) => {
                let secrets = quic_secrets_from_handshake_keys(&keys);
                self.handshake_secrets = Some(secrets.clone());
                self.state = QuicDriverState::Tls13Encrypted { handshake };
                Ok(QuicHandshakeOutput::HandshakeSecretsReady {
                    to_send: Vec::new(),
                    secrets,
                })
            }
            HandshakeAction::RetryClientHello(ch2) => {
                self.state = QuicDriverState::WaitServerHello { handshake };
                Ok(QuicHandshakeOutput::SendData(ch2))
            }
            _ => Err(TlsError::HandshakeFailure(
                "unexpected action after QUIC ServerHello".into(),
            )),
        }
    }

    fn finish_quic_tls13(&mut self, complete: HandshakeComplete) -> Result<QuicHandshakeOutput> {
        // Same rule as the TCP path: an ECH offer the server did not accept must
        // not carry application data (RFC 9849 §6.1.6). Abort before any traffic
        // keys or session-ticket context are produced, and surface the
        // retry_configs. QUIC signals the alert through a CRYPTO_ERROR frame
        // rather than a TLS alert record, which the caller maps from this error.
        if complete.ech_offered && !complete.ech_accepted {
            tracing::warn!(
                host = %self.config.tls.hostname,
                retry_configs = complete.ech_retry_configs.as_ref().map_or(0, |c| c.len()),
                "tls.ech_rejected — aborting QUIC handshake",
            );
            return Err(TlsError::EchRejected {
                retry_configs: complete.ech_retry_configs.clone(),
            });
        }

        let mut to_send = Vec::new();
        if let Some(ref cee) = complete.client_encrypted_extensions {
            to_send.extend_from_slice(cee);
        }
        if let Some(ref certificate) = complete.client_certificate {
            to_send.extend_from_slice(certificate);
        }
        to_send.extend_from_slice(&complete.client_finished);

        let host_key = format!("{}:{}", self.config.tls.hostname, self.config.tls.port);
        let session_ticket_ctx = if self.config.tls.profile.session_resumption.store_tickets {
            self.config
                .tls
                .session_store
                .as_ref()
                .map(|store| SessionTicketContext {
                    resumption_master_secret: complete.resumption_master_secret.clone(),
                    hkdf_algorithm: complete.traffic_secrets.hkdf_algorithm,
                    aead_algorithm: complete.traffic_secrets.aead_algorithm,
                    cipher_suite: complete.negotiated_cipher_suite,
                    alpn: complete.negotiated_alpn.clone(),
                    alps: complete.alps.clone(),
                    peer_transport_parameters: complete
                        .peer_quic_transport_params
                        .as_ref()
                        .map(crate::extensions::quic_transport_params::encode_transport_params),
                    store: Arc::clone(store),
                    host_key,
                })
        } else {
            None
        };

        let app_secrets = quic_secrets_from_traffic_secrets(&complete.traffic_secrets);
        let handshake_secrets = self.handshake_secrets.clone().ok_or_else(|| {
            TlsError::HandshakeFailure("missing QUIC handshake traffic secrets".to_string())
        })?;

        self.state = QuicDriverState::Complete;
        Ok(QuicHandshakeOutput::Done {
            to_send,
            result: Box::new(QuicHandshakeResult {
                negotiated_alpn: complete.negotiated_alpn,
                negotiated_cipher_suite: Some(complete.negotiated_cipher_suite),
                handshake_secrets,
                app_secrets: app_secrets.clone(),
                post_handshake: Some(PostHandshakeState {
                    server_app_secret: app_secrets.server_secret.clone(),
                    client_app_secret: app_secrets.client_secret.clone(),
                    hkdf_algorithm: app_secrets.hkdf_algorithm,
                    aead_algorithm: app_secrets.aead_algorithm,
                    exporter_master_secret: complete.traffic_secrets.exporter_master_secret.clone(),
                }),
                session_ticket_ctx,
                peer_transport_params: complete.peer_quic_transport_params,
                early_data_accepted: complete.early_data_accepted,
                session_resumed: complete.session_resumed,
            }),
        })
    }
}

fn quic_secrets_from_handshake_keys(keys: &HandshakeKeys) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        client_secret: keys.client_secret.clone(),
        server_secret: keys.server_secret.clone(),
        hkdf_algorithm: keys.hkdf_algorithm,
        aead_algorithm: keys.aead_algorithm,
    }
}

fn quic_secrets_from_traffic_secrets(secrets: &TrafficSecrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        client_secret: secrets.client_app_secret.clone(),
        server_secret: secrets.server_app_secret.clone(),
        hkdf_algorithm: secrets.hkdf_algorithm,
        aead_algorithm: secrets.aead_algorithm,
    }
}

fn take_complete_handshake_messages(input: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    let mut pos = 0usize;
    while pos < input.len() {
        if input.len() - pos < 4 {
            break;
        }

        let length = ((input[pos + 1] as usize) << 16)
            | ((input[pos + 2] as usize) << 8)
            | (input[pos + 3] as usize);
        let Some(msg_end) = pos.checked_add(4 + length) else {
            return Err(TlsError::UnexpectedMessage(
                "handshake message length overflow".to_string(),
            ));
        };
        if msg_end > input.len() {
            break;
        }
        pos = msg_end;
    }

    if pos == 0 {
        return Ok(None);
    }

    Ok(Some(input.drain(..pos).collect()))
}

fn take_next_handshake_message(input: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if input.len() < 4 {
        return Ok(None);
    }

    let length = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | (input[3] as usize);
    let Some(end) = 4usize.checked_add(length) else {
        return Err(TlsError::UnexpectedMessage(
            "handshake message length overflow".to_string(),
        ));
    };
    if end > input.len() {
        return Ok(None);
    }

    Ok(Some(input.drain(..end).collect()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadAlgorithm;
    use crate::crypto::hkdf::HkdfAlgorithm;
    use crate::extensions::quic_transport_params::{
        encode_transport_params, param_id, QuicTransportParam, QuicTransportParams,
    };
    use crate::session_store::{InMemorySessionStore, SessionTicketData, TicketTlsVersion};
    use std::sync::Arc;
    use std::time::Instant;

    // -----------------------------------------------------------------------
    // Handshake-message reassembly across records (RFC 8446 §5.1)
    //
    // A handshake message MAY be fragmented across several TLS records, and
    // several messages MAY be coalesced into one. The TLS 1.2 and 1.3 driver
    // paths both feed decrypted record payloads through
    // `take_complete_handshake_messages`, which drains only *complete* messages
    // and retains any partial trailer for the next record. These tests lock in
    // that behaviour — the exact scenario that made Facebook (a fragmented
    // Certificate flight) fail with "truncated handshake message in record".
    // -----------------------------------------------------------------------

    /// Build a handshake message: 1-byte type + 3-byte length + `len` body bytes.
    fn hs_msg(msg_type: u8, fill: u8, len: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(4 + len);
        m.push(msg_type);
        m.push((len >> 16) as u8);
        m.push((len >> 8) as u8);
        m.push(len as u8);
        m.resize(4 + len, fill);
        m
    }

    fn hrr_message(session_id: &[u8], cipher_suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&crate::handshake::server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![crate::handshake::handshake_type::SERVER_HELLO];
        let body_len = body.len();
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn malformed_ccs_before_server_hello_matches_browser_alerts() {
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            let description = if profile.tls_client_hello_style
                == crate::profile::types::TlsClientHelloStyle::FirefoxNss
            {
                AlertDescription::IllegalParameter
            } else {
                AlertDescription::UnexpectedMessage
            };
            for payload in [&[][..], &[2][..], &[1, 1][..]] {
                let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
                config.profile = profile.clone();
                let mut driver = HandshakeDriver::new(config);
                driver.start().unwrap();
                let mut record = vec![20, 3, 3, 0, payload.len() as u8];
                record.extend_from_slice(payload);
                driver.feed(&record[..4]);
                assert!(matches!(
                    driver.progress().unwrap(),
                    HandshakeOutput::NeedData
                ));
                driver.feed(&record[4..]);
                assert!(
                    matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == description)
                );
                assert_eq!(
                    driver.take_pending_alert().unwrap(),
                    [21, 3, 1, 0, 2, 2, description.as_byte()]
                );
                assert!(driver.take_pending_alert().is_none());
            }
        }
    }

    #[test]
    fn browser_ccs_waits_for_the_final_client_flight_after_server_hello() {
        use crate::crypto::kx::{generate_key_pair, KxGroup};
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            let chromium = profile.tls_client_hello_style
                == crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl;
            let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
            config.profile = profile;
            let mut driver = HandshakeDriver::new(config);
            let ch = driver.start().unwrap();
            let hello = &ch[5..];
            let session_id = &hello[39..39 + hello[38] as usize];
            let key = generate_key_pair(KxGroup::X25519).unwrap();
            let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
            extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
            extensions.extend_from_slice(&[0, 29]);
            extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&key.public_key);
            let mut sh = hrr_message(session_id, 0x1301, &extensions);
            sh[6..38].fill(0x55);
            let mut record = vec![22, 3, 3];
            record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            record.extend_from_slice(&sh);
            driver.feed(&record);
            let HandshakeOutput::SendData(bytes) = driver.progress().unwrap() else {
                panic!("ServerHello must install keys");
            };
            assert!(
                bytes.is_empty(),
                "browser must not flush CCS upon ServerHello alone"
            );
            driver.feed(&[20, 3, 3, 0, 1, 1]);
            assert!(matches!(
                driver.progress().unwrap(),
                HandshakeOutput::NeedData
            ));
            assert!(driver.take_pending_alert().is_none());
            driver.feed(&[23, 3, 3, 0xff, 0xff]);
            assert!(
                matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. })
                if alert.description == AlertDescription::RecordOverflow)
            );
            let failure = driver.take_pending_alert().unwrap();
            let encrypted = if chromium {
                assert_eq!(&failure[..6], &[20, 3, 3, 0, 1, 1]);
                &failure[6..]
            } else {
                &failure[..]
            };
            assert_eq!(&encrypted[..5], &[23, 3, 3, 0, 19]);
            assert_eq!(encrypted.len(), 24);
            assert!(driver.take_pending_alert().is_none());
        }
    }

    #[test]
    fn local_hrr_error_queues_plaintext_fatal_alert() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let already_offered = profile.key_share_curves[0];
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.profile = profile;
        config.hostname = "example.com".to_string();
        config.verification_policy = VerificationPolicy::Insecure;
        let mut driver = HandshakeDriver::new(config);

        let client_hello_record = driver.start().unwrap();
        let client_hello = &client_hello_record[5..];
        let session_id_len = client_hello[38] as usize;
        let session_id = &client_hello[39..39 + session_id_len];

        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
        extensions.extend_from_slice(&already_offered.to_be_bytes());
        let hrr = hrr_message(session_id, cipher_suite, &extensions);
        let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(hrr.len() as u16).to_be_bytes());
        record.extend_from_slice(&hrr);
        driver.feed(&record);

        let error = match driver.progress() {
            Err(error) => error,
            Ok(_) => panic!("invalid HRR must fail"),
        };
        assert!(matches!(
            error,
            TlsError::LocalAlert {
                alert: crate::error::TlsAlert {
                    description: crate::error::AlertDescription::IllegalParameter,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            driver.take_pending_alert().as_deref(),
            Some(&[20, 3, 3, 0, 1, 1, content_type::ALERT, 3, 3, 0, 2, 2, 0x2f][..])
        );
        assert!(driver.take_pending_alert().is_none());
    }

    #[test]
    fn reassembly_single_complete_message() {
        let msg = hs_msg(0x0b, 0xAA, 10);
        let mut buf = msg.clone();
        let out = take_complete_handshake_messages(&mut buf).unwrap();
        assert_eq!(out.as_deref(), Some(msg.as_slice()));
        assert!(buf.is_empty(), "buffer fully drained");
    }

    #[test]
    fn reassembly_coalesced_messages_drain_together() {
        let a = hs_msg(0x08, 0x01, 3);
        let b = hs_msg(0x0b, 0x02, 5);
        let mut buf = [a.clone(), b.clone()].concat();
        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, [a, b].concat());
        assert!(buf.is_empty());
    }

    #[test]
    fn reassembly_message_fragmented_across_records() {
        // The core regression: one message split across two records. The first
        // record carries only part of it → nothing surfaced yet; the remainder
        // in the next record completes it. (Previously errored "truncated".)
        let msg = hs_msg(0x0b, 0xCD, 20);
        let (head, tail) = msg.split_at(11);

        let mut buf = head.to_vec();
        assert!(
            take_complete_handshake_messages(&mut buf)
                .unwrap()
                .is_none(),
            "a partial message must not be surfaced"
        );
        assert_eq!(buf, head, "partial bytes retained for the next record");

        buf.extend_from_slice(tail);
        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, msg, "reassembled the full message");
        assert!(buf.is_empty());
    }

    #[test]
    fn reassembly_partial_trailer_retained() {
        // A record with a complete message followed by the start of another:
        // the complete one drains, the partial trailer stays for next time.
        let done = hs_msg(0x0e, 0x00, 0); // ServerHelloDone (empty body)
        let next = hs_msg(0x0b, 0xEE, 30);
        let mut buf = [done.clone(), next[..6].to_vec()].concat();

        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, done, "only the complete message drains");
        assert_eq!(buf, next[..6], "partial trailer retained");

        buf.extend_from_slice(&next[6..]);
        let out2 = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out2, next);
    }

    #[test]
    fn reassembly_oversized_length_is_incomplete_not_panic() {
        // A header claiming a huge body with no data behind it is treated as
        // incomplete (wait for more), never a panic or a bogus drain.
        let mut buf = vec![0x0b, 0xff, 0xff, 0xff];
        assert!(take_complete_handshake_messages(&mut buf)
            .unwrap()
            .is_none());
        assert_eq!(buf, vec![0x0b, 0xff, 0xff, 0xff], "left intact");
    }

    fn make_tls13_ticket() -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x01, 0x02, 0x03],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
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

    fn make_quic_early_data_ticket() -> SessionTicketData {
        SessionTicketData {
            alpn: Some("h3".to_string()),
            max_early_data_size: 16_384,
            peer_transport_parameters: Some(vec![0x0f, 0x00]),
            used_extended_master_secret: None,
            ..make_tls13_ticket()
        }
    }

    fn make_tls12_ticket() -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x10, 0x20, 0x30, 0x40],
            resumption_psk: Vec::new(),
            tls_version: TicketTlsVersion::Tls12,
            cipher_suite: 0xC02F,
            lifetime_secs: 3600,
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

    fn make_config_with_store(store: Arc<InMemorySessionStore>) -> HandshakeConfig {
        let profile = crate::profile::presets::chrome_144();
        HandshakeConfig {
            profile,
            hostname: "example.com".to_string(),
            port: 443,
            verification_policy: VerificationPolicy::default(),
            alps_payload: None,
            session_store: Some(store as Arc<dyn SessionStore>),
            ech_config_list: None,
            custom_ca_anchors: None,
            keylog_callback: None,
            client_hello_callback: None,
        }
    }

    fn ticket_test_ech_config() -> Vec<u8> {
        let public_name = b"public.example.com";
        let mut contents = vec![42, 0, 32, 0, 32];
        contents.extend_from_slice(&[0x42; 32]);
        contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 64]);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name);
        contents.extend_from_slice(&[0, 0]);
        let mut config = vec![0xfe, 0x0d];
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = (config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&config);
        list
    }

    #[test]
    fn real_ech_ignores_cached_tls12_ticket_but_grease_keeps_it() {
        for real_ech in [false, true] {
            let store = Arc::new(InMemorySessionStore::new());
            let ticket = make_tls12_ticket();
            let expected_length = ticket.ticket.len();
            store.store("example.com:443", ticket);
            let mut config = make_config_with_store(store);
            if real_ech {
                config.ech_config_list = Some(ticket_test_ech_config());
            }
            let mut driver = HandshakeDriver::new(config);
            let hello = driver.start().unwrap();
            let (length, has_psk) = scan_ch_extensions(&hello);
            assert_eq!(length, if real_ech { 0 } else { expected_length });
            assert!(!has_psk);
            assert_eq!(driver.original_ticket.is_none(), real_ech);
        }
    }

    fn scalar_test_tls12_server_hello(cipher: u16, compression: u8, session_id_len: u8) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x55; 32]);
        body.push(session_id_len);
        body.extend(std::iter::repeat_n(0xa5, session_id_len as usize));
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(compression);
        let mut message = vec![2, 0, 0, body.len() as u8];
        message.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn version_selection_quic_rejects_invalid_extension_payloads() {
        for (profile, nss) in [
            (crate::profile::presets::chrome_155(), false),
            (crate::profile::presets::firefox_156(), true),
        ] {
            for (version, expected) in [
                (&[3][..], AlertDescription::DecodeError),
                (
                    &[3, 4, 0][..],
                    if nss {
                        AlertDescription::IllegalParameter
                    } else {
                        AlertDescription::DecodeError
                    },
                ),
                (
                    &[3, 3][..],
                    if nss {
                        AlertDescription::IllegalParameter
                    } else {
                        AlertDescription::ProtocolVersion
                    },
                ),
            ] {
                let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
                config.profile = profile.clone();
                let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
                driver.start().unwrap();
                let mut extensions = vec![0, 43];
                extensions.extend_from_slice(&(version.len() as u16).to_be_bytes());
                extensions.extend_from_slice(version);
                let mut sh = hrr_message(&[], 0x1301, &extensions);
                sh[6..38].fill(0x55);
                driver.feed(&sh);
                assert!(
                    matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == expected)
                );
            }
        }
    }

    #[test]
    fn tls12_fallback_is_allowed_initially_but_never_after_hrr() {
        for profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            for retry in [false, true] {
                let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
                config.profile = profile.clone();
                let mut driver = HandshakeDriver::new(config);
                let ch = driver.start().unwrap();
                let hello = &ch[5..];
                let sid = &hello[39..39 + hello[38] as usize];
                if retry {
                    let hrr = hrr_message(sid, 0x1301, &[0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 24]);
                    let mut record = vec![22, 3, 3];
                    record.extend_from_slice(&(hrr.len() as u16).to_be_bytes());
                    record.extend_from_slice(&hrr);
                    driver.feed(&record);
                    assert!(matches!(
                        driver.progress().unwrap(),
                        HandshakeOutput::SendData(_)
                    ));
                }
                driver.feed(&scalar_test_tls12_server_hello(0xc02f, 0, 0));
                if retry {
                    assert!(
                        matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. })
                        if alert.description == AlertDescription::IllegalParameter)
                    );
                    assert_eq!(
                        driver.take_pending_alert(),
                        Some(vec![21, 3, 3, 0, 2, 2, 47])
                    );
                } else {
                    assert!(matches!(
                        driver.progress().unwrap(),
                        HandshakeOutput::NeedData
                    ));
                }
            }
        }
    }

    #[test]
    fn invalid_supported_versions_never_falls_back_to_tls12() {
        for (profile, nss) in [
            (crate::profile::presets::chrome_155(), false),
            (crate::profile::presets::firefox_156(), true),
        ] {
            for case in [2, 0, 1] {
                let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
                config.profile = profile.clone();
                let mut driver = HandshakeDriver::new(config);
                driver.start().unwrap();
                let version: &[u8] = match case {
                    0 => &[3],
                    1 => &[3, 4, 0],
                    _ => &[3, 3],
                };
                let mut record = scalar_test_tls12_server_hello(0xc02f, 0, 0);
                record.extend_from_slice(&((4 + version.len()) as u16).to_be_bytes());
                record.extend_from_slice(&[0, 43]);
                record.extend_from_slice(&(version.len() as u16).to_be_bytes());
                record.extend_from_slice(version);
                let record_len = (record.len() - 5) as u16;
                record[3..5].copy_from_slice(&record_len.to_be_bytes());
                record[8] = (record.len() - 9) as u8;
                driver.feed(&record);
                let expected = match (nss, case) {
                    (false, 2) => AlertDescription::UnsupportedExtension,
                    (true, 1 | 2) => AlertDescription::IllegalParameter,
                    _ => AlertDescription::DecodeError,
                };
                assert!(
                    matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == expected),
                    "nss={nss} case={case}"
                );
                assert_eq!(
                    driver.take_pending_alert(),
                    Some(vec![
                        21,
                        3,
                        if !nss && case == 2 { 3 } else { 1 },
                        0,
                        2,
                        2,
                        expected.as_byte()
                    ])
                );
            }
        }
    }

    #[test]
    fn tls12_driver_rejects_unoffered_cipher_and_nonnull_compression() {
        for unoffered_cipher in [false, true] {
            let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
            if unoffered_cipher {
                config
                    .profile
                    .cipher_suites
                    .retain(|cipher| *cipher != 0xc02f);
            }
            let mut driver = HandshakeDriver::new(config);
            driver.start().unwrap();
            driver.feed(&scalar_test_tls12_server_hello(
                0xc02f,
                if unoffered_cipher { 0 } else { 1 },
                0,
            ));
            assert!(
                matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
            );
        }
    }

    #[test]
    fn tls12_driver_respects_tls13_minimum() {
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.profile.tls_min_version = crate::profile::types::TlsVersion::Tls13;
        let mut driver = HandshakeDriver::new(config);
        driver.start().unwrap();
        driver.feed(&scalar_test_tls12_server_hello(0xc02f, 0, 0));
        assert!(
            matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::ProtocolVersion)
        );
    }

    #[test]
    fn tls12_driver_rejects_session_id_over_32_bytes() {
        let mut driver = HandshakeDriver::new(make_config_with_store(Arc::new(
            InMemorySessionStore::new(),
        )));
        driver.start().unwrap();
        driver.feed(&scalar_test_tls12_server_hello(0xc02f, 0, 33));
        assert!(
            matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
        );
    }

    #[test]
    fn tcp_version_selection_uses_actual_supported_versions_override() {
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config
            .profile
            .extensions
            .iter_mut()
            .find(|extension| extension.extension_type == 43)
            .unwrap()
            .source = crate::profile::types::ExtensionSource::RawBytes {
            data: "020304".into(),
        };
        let mut driver = HandshakeDriver::new(config);
        driver.start().unwrap();
        driver.feed(&scalar_test_tls12_server_hello(0xc02f, 0, 0));
        assert!(
            matches!(driver.progress(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::ProtocolVersion)
        );
    }

    /// Helper: scan ClientHello extensions and return (session_ticket_data_len, has_pre_shared_key).
    fn scan_ch_extensions(ch_record: &[u8]) -> (usize, bool) {
        let ch_msg = &ch_record[5..]; // skip record header
        let sid_len = ch_msg[38] as usize;
        let cs_start = 39 + sid_len;
        let cs_len = u16::from_be_bytes([ch_msg[cs_start], ch_msg[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = ch_msg[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;
        let ext_total_len =
            u16::from_be_bytes([ch_msg[ext_len_pos], ch_msg[ext_len_pos + 1]]) as usize;
        let ext_start = ext_len_pos + 2;
        let ext_end = ext_start + ext_total_len;

        let mut pos = ext_start;
        let mut session_ticket_len = 0usize;
        let mut found_psk = false;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]);
            let ext_len = u16::from_be_bytes([ch_msg[pos + 2], ch_msg[pos + 3]]) as usize;
            if ext_type == 0x0023 {
                session_ticket_len = ext_len;
            }
            if ext_type == 0x0029 {
                found_psk = true;
            }
            pos += 4 + ext_len;
        }
        (session_ticket_len, found_psk)
    }

    fn parse_raw_client_hello_extensions(ch_msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let body = &ch_msg[4..];
        let sid_len = body[34] as usize;
        let cs_start = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[cs_start], body[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = body[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;
        let ext_total_len = u16::from_be_bytes([body[ext_len_pos], body[ext_len_pos + 1]]) as usize;
        let ext_start = ext_len_pos + 2;
        let ext_end = ext_start + ext_total_len;

        let mut extensions = Vec::new();
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            let data_start = pos + 4;
            let data_end = data_start + ext_len;
            extensions.push((ext_type, body[data_start..data_end].to_vec()));
            pos = data_end;
        }

        extensions
    }

    #[test]
    fn tls13_ticket_uses_psk_not_session_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_tls13_ticket());

        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0, "session_ticket must be empty for TLS 1.3 PSK");
        assert!(has_psk, "pre_shared_key must be present for TLS 1.3 ticket");
    }

    #[test]
    fn client_hello_callback_fires_from_driver_with_handshake_message() {
        use std::sync::Mutex;
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);

        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.client_hello_callback = Some(Arc::new(move |bytes: &[u8]| {
            sink.lock().unwrap().extend_from_slice(bytes);
        }));

        let mut driver = HandshakeDriver::new(config);
        let ch_record = driver.start().unwrap();

        let observed = captured.lock().unwrap().clone();
        // The driver itself fires the hook (it was previously dead at the lktls
        // layer — only lkrequest's connector invoked it).
        assert!(
            !observed.is_empty(),
            "client_hello_callback must fire from the driver"
        );
        // It receives the ClientHello *handshake message* (0x01), not the
        // record-framed wire bytes (0x16) that `start()` returns.
        assert_eq!(
            observed[0], 0x01,
            "callback must get the handshake message (0x01), not the record"
        );
        assert_eq!(ch_record[0], 0x16, "start() returns the TLS record (0x16)");
        // No data loss: the observed handshake message is exactly the record
        // payload (the TLS record header is 5 bytes).
        assert_eq!(
            &observed[..],
            &ch_record[5..],
            "callback bytes must equal the record payload"
        );
    }

    #[test]
    fn tls12_ticket_uses_session_ticket_not_psk() {
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_tls12_ticket());

        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert!(
            st_len > 0,
            "session_ticket must carry data for TLS 1.2 ticket"
        );
        assert!(
            !has_psk,
            "pre_shared_key must NOT be present for TLS 1.2 ticket"
        );
    }

    #[test]
    fn alpn_mismatch_skips_tls13_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_tls13_ticket();
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let mut config = make_config_with_store(store);
        config.profile.alpn_protocols = vec!["http/1.1".to_string()];

        let mut driver = HandshakeDriver::new(config);
        let ch = driver.start().unwrap();
        let (_, has_psk) = scan_ch_extensions(&ch);

        assert!(
            !has_psk,
            "pre_shared_key must NOT be present on ALPN mismatch"
        );
        assert!(driver.original_ticket.is_none());
    }

    #[test]
    fn alpn_mismatch_skips_tls12_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_tls12_ticket();
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let mut config = make_config_with_store(store);
        config.profile.alpn_protocols = vec!["http/1.1".to_string()];

        let mut driver = HandshakeDriver::new(config);
        let ch = driver.start().unwrap();
        let (st_len, _) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0, "session_ticket must be empty on ALPN mismatch");
        assert!(driver.original_ticket.is_none());
    }

    #[test]
    fn no_ticket_no_psk() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0);
        assert!(!has_psk);
    }

    #[test]
    fn quic_driver_start_returns_raw_client_hello_with_empty_session_id_and_transport_params() {
        let transport_parameters = encode_transport_params(&QuicTransportParams::new(vec![
            QuicTransportParam::new(
                param_id::INITIAL_SOURCE_CONNECTION_ID,
                vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
            ),
            QuicTransportParam::new(param_id::INITIAL_MAX_DATA, vec![0x40, 0x64]),
        ]));

        let mut driver = QuicHandshakeDriver::new(
            make_config_with_store(Arc::new(InMemorySessionStore::new()))
                .into_quic(transport_parameters.clone()),
        );
        let ch = driver.start().unwrap();

        assert_eq!(ch[0], 0x01, "must return raw ClientHello handshake bytes");
        let body_len = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | (ch[3] as usize);
        assert_eq!(body_len, ch.len() - 4);

        let body = &ch[4..];
        assert_eq!(
            body[34], 0,
            "QUIC ClientHello must use empty legacy_session_id"
        );

        let extensions = parse_raw_client_hello_extensions(&ch);
        let quic_tp = extensions
            .into_iter()
            .find(|(extension_type, _)| *extension_type == 0x0039)
            .map(|(_, data)| data);

        assert_eq!(quic_tp, Some(transport_parameters));
    }

    #[test]
    fn quic_chrome_profile_inserts_early_data_before_supported_versions_when_ticket_allows_0rtt() {
        let transport_parameters =
            encode_transport_params(&QuicTransportParams::new(vec![QuicTransportParam::new(
                param_id::INITIAL_SOURCE_CONNECTION_ID,
                Vec::new(),
            )]));
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_quic_early_data_ticket());
        let mut config = make_config_with_store(store);
        config.profile = crate::profile::presets::chrome_146_quic();
        config.alps_payload = Some(vec![0x01, 0x40, 0x00]);

        let mut driver = QuicHandshakeDriver::new(config.into_quic(transport_parameters));
        let ch = driver.start().unwrap();
        let extension_types = parse_raw_client_hello_extensions(&ch)
            .into_iter()
            .map(|(extension_type, _)| extension_type)
            .collect::<Vec<_>>();
        let is_grease = |value: &u16| {
            let hi = (value >> 8) as u8;
            let lo = (value & 0xff) as u8;
            hi == lo && (hi & 0x0f) == 0x0a
        };
        let real_extension_types = extension_types
            .iter()
            .copied()
            .filter(|extension_type| !is_grease(extension_type))
            .collect::<Vec<_>>();

        assert_eq!(
            real_extension_types,
            vec![45, 10, 51, 65037, 16, 0, 27, 13, 42, 43, 57, 17613, 41]
        );
    }

    #[test]
    fn quic_driver_advertises_alps_when_payload_is_configured() {
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.profile.alpn_protocols = vec!["h3".to_string()];
        config.profile.alps_protocols = Some(vec!["h3".to_string()]);
        config.alps_payload = Some(vec![0x01, 0x40, 0x00]);

        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let ch = driver.start().unwrap();

        let alps = parse_raw_client_hello_extensions(&ch)
            .into_iter()
            .find(|(extension_type, _)| *extension_type == 0x44cd)
            .map(|(_, data)| data);

        assert_eq!(alps, Some(vec![0x00, 0x03, 0x02, b'h', b'3']));
    }

    /// ALPS advertisement in the ClientHello is DECOUPLED from the client's
    /// settings payload. The ClientHello ALPS extension always carries the
    /// profile's protocol list (`h2`); the settings payload rides separately in
    /// the Client EncryptedExtensions. Real Chrome advertises ALPS `h2` with an
    /// EMPTY settings payload, so `Some(vec![])` MUST still advertise ALPS.
    ///   None    => no ALPS (H1-only request path)
    ///   Some(_) => advertise ALPS `h2` (payload content is irrelevant *here*)
    #[test]
    fn alps_advertisement_is_decoupled_from_settings_payload() {
        // chrome_144: alps_protocols = Some(["h2"]) and lists 0x44cd.
        let ch_alps = |payload: Option<Vec<u8>>| -> Option<Vec<u8>> {
            let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
            config.alps_payload = payload;
            let mut driver = HandshakeDriver::new(config);
            let ch = driver.start().unwrap();
            // TCP .start() returns a TLS record; skip the 5-byte record header to
            // get the handshake message that parse_raw_client_hello_extensions wants.
            parse_raw_client_hello_extensions(&ch[5..])
                .into_iter()
                .find(|(t, _)| *t == 0x44cd)
                .map(|(_, d)| d)
        };
        // The ClientHello ALPS extension body is always the h2 protocol list,
        // never the settings payload.
        let h2_protocol_list = vec![0x00, 0x03, 0x02, b'h', b'2'];

        assert_eq!(ch_alps(None), None, "None ⇒ no ALPS (H1-only)");
        assert_eq!(
            ch_alps(Some(vec![])),
            Some(h2_protocol_list.clone()),
            "Some(empty) ⇒ ALPS advertises h2 (Chrome: advertise + empty settings)"
        );
        assert_eq!(
            ch_alps(Some(vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x64])),
            Some(h2_protocol_list),
            "Some(non-empty settings) ⇒ ClientHello ALPS still shows the h2 \
             protocol list, not the settings payload (payload rides in Client EE)"
        );
    }

    #[test]
    fn key_update_response_message_format() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let (msg, _aead) = state.build_key_update_response().unwrap();

        assert_eq!(msg, vec![0x18, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn key_update_response_rotates_client_secret() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let before = state.client_app_secret.clone();
        let _ = state.build_key_update_response().unwrap();
        assert_ne!(before, state.client_app_secret);

        let mid = state.client_app_secret.clone();
        let _ = state.build_key_update_response().unwrap();
        assert_ne!(mid, state.client_app_secret);
    }

    #[test]
    fn key_update_read_rotates_server_secret() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let before = state.server_app_secret.clone();
        let _ = state.process_key_update().unwrap();
        assert_ne!(before, state.server_app_secret);
    }

    // -----------------------------------------------------------------------
    // RFC 8449 `record_size_limit` reaches the record writer
    //
    // Parsing the peer's limit is worthless if it never lands on the writer
    // that frames application data, so these lock in the hand-off at both
    // completion points.
    // -----------------------------------------------------------------------

    fn make_config() -> HandshakeConfig {
        HandshakeConfig {
            profile: crate::profile::presets::firefox_147(),
            hostname: "example.com".to_string(),
            port: 443,
            verification_policy: VerificationPolicy::default(),
            alps_payload: None,
            session_store: None,
            ech_config_list: None,
            custom_ca_anchors: None,
            keylog_callback: None,
            client_hello_callback: None,
        }
    }

    fn make_handshake_complete(peer_record_size_limit: Option<u16>) -> HandshakeComplete {
        HandshakeComplete {
            client_end_of_early_data: None,
            client_encrypted_extensions: None,
            client_certificate: None,
            client_finished: hs_msg(crate::handshake::handshake_type::FINISHED, 0xAA, 32),
            traffic_secrets: TrafficSecrets {
                aead_algorithm: AeadAlgorithm::Aes128Gcm,
                hkdf_algorithm: HkdfAlgorithm::Sha256,
                client_key: vec![0x11; 16],
                client_iv: vec![0x22; 12],
                server_key: vec![0x33; 16],
                server_iv: vec![0x44; 12],
                server_app_secret: vec![0x55; 32],
                client_app_secret: vec![0x66; 32],
                exporter_master_secret: vec![0x77; 32],
            },
            negotiated_alpn: Some("h2".to_string()),
            alps: AlpsSessionState::NotNegotiated,
            peer_record_size_limit,
            resumption_master_secret: vec![0x88; 32],
            negotiated_cipher_suite: 0x1301,
            server_certificates: Vec::new(),
            ech_retry_configs: None,
            ech_accepted: false,
            ech_offered: false,
            peer_quic_transport_params: None,
            early_data_accepted: false,
            session_resumed: false,
        }
    }

    fn completed_writer_limit(peer_record_size_limit: Option<u16>) -> Option<u16> {
        let mut driver = HandshakeDriver::new(make_config());
        let output = driver
            .finish_tls13(make_handshake_complete(peer_record_size_limit))
            .expect("TLS 1.3 completion");
        match output {
            HandshakeOutput::Done { result, .. } => result.writer.peer_record_size_limit(),
            _ => panic!("finish_tls13 must complete the handshake"),
        }
    }

    #[test]
    fn tls13_completion_installs_the_peer_record_size_limit_on_the_writer() {
        assert_eq!(
            completed_writer_limit(Some(512)),
            Some(512),
            "the server's EncryptedExtensions limit must reach the record writer"
        );
    }

    #[test]
    fn tls13_completion_without_a_peer_limit_leaves_the_writer_unbounded() {
        assert_eq!(
            completed_writer_limit(None),
            None,
            "no server limit must leave the writer chunking at the protocol maximum"
        );
    }

    #[test]
    fn early_flight_combination_writes_alps_certificate_finished_in_one_handshake_epoch() {
        let key = [0xa1; 16];
        let iv = [0xa2; 12];
        let mut driver = HandshakeDriver::new(make_config());
        driver
            .writer
            .set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        let mut complete = make_handshake_complete(None);
        complete.client_encrypted_extensions = Some(vec![8, 0, 0, 6, 0, 4, 0x44, 0xcd, 0, 0]);
        complete.client_certificate = Some(vec![11, 0, 0, 4, 0, 0, 0, 0]);
        let expected = [
            complete.client_encrypted_extensions.clone().unwrap(),
            complete.client_certificate.clone().unwrap(),
            complete.client_finished.clone(),
        ];
        let HandshakeOutput::Done { to_send, .. } = driver.finish_tls13(complete).unwrap() else {
            panic!("client flight must complete");
        };
        let mut reader = RecordReader::new();
        reader.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        reader.feed(&to_send);
        for message in expected {
            let record = reader.next_record().unwrap().unwrap();
            assert_eq!(record.content_type, content_type::HANDSHAKE);
            assert_eq!(record.payload, message);
        }
        assert!(reader.next_record().unwrap().is_none());
    }

    #[derive(Debug)]
    struct QuicClientCertificateFlight {
        message_types: Vec<u8>,
        certificate_matches: bool,
        alps_matches: bool,
        finished_matches: bool,
        early_data_accepted: bool,
    }

    fn quic_certificate_message(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(payload);
        message
    }

    fn quic_certificate_finished(secret: &[u8], transcript: &[u8]) -> Vec<u8> {
        let finished_key = crate::crypto::hkdf::hkdf_expand_label(
            HkdfAlgorithm::Sha256,
            secret,
            "finished",
            &[],
            32,
        )
        .unwrap();
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, transcript);
        aws_lc_rs::hmac::sign(
            &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &finished_key),
            hash.as_ref(),
        )
        .as_ref()
        .to_vec()
    }

    fn quic_client_certificate_flight(
        request_certificate: bool,
        alps: bool,
    ) -> QuicClientCertificateFlight {
        use crate::crypto::kx::{generate_key_pair, KxGroup};
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["example.com".into()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        let anchor =
            crate::verify::certchain::parse_trust_anchor_from_der(certificate.der()).unwrap();
        let signer = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &signing_key.serialize_der(),
        )
        .unwrap();
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_quic_early_data_ticket();
        ticket.max_early_data_size = u32::MAX;
        store.store("example.com:443", ticket);
        let mut config = make_config_with_store(store);
        config.profile = crate::profile::presets::chrome_155_quic();
        config.alps_payload = alps.then(Vec::new);
        config.custom_ca_anchors = Some(Arc::new(vec![anchor]));
        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let hello = driver.start().unwrap();
        assert!(driver.early_data_offer().is_some());

        let key = generate_key_pair(KxGroup::X25519).unwrap();
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
        extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&[0, 29]);
        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key.public_key);
        let mut server_hello = hrr_message(&[], 0x1301, &extensions);
        server_hello[6..38].fill(0x55);
        let mut transcript = hello;
        transcript.extend_from_slice(&server_hello);
        driver.feed(&server_hello);
        let QuicHandshakeOutput::HandshakeSecretsReady { secrets, .. } = driver.progress().unwrap()
        else {
            panic!("ServerHello must install QUIC handshake secrets");
        };

        let mut ee_extensions = vec![0, 16, 0, 5, 0, 3, 2, b'h', b'3', 0, 57, 0, 0];
        if alps {
            ee_extensions.extend_from_slice(&[0x44, 0xcd, 0, 0]);
        }
        let mut ee_body = (ee_extensions.len() as u16).to_be_bytes().to_vec();
        ee_body.extend_from_slice(&ee_extensions);
        let mut server_flight = quic_certificate_message(8, &ee_body);
        if request_certificate {
            server_flight.extend_from_slice(&quic_certificate_message(
                13,
                &[0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3],
            ));
        }
        let der = certificate.der().as_ref();
        let mut cert_body = vec![0];
        cert_body.extend_from_slice(&((der.len() + 5) as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(der);
        cert_body.extend_from_slice(&[0, 0]);
        server_flight.extend_from_slice(&quic_certificate_message(11, &cert_body));
        transcript.extend_from_slice(&server_flight);
        let mut signed = vec![0x20; 64];
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        signed.extend_from_slice(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &transcript).as_ref(),
        );
        let signature = signer
            .sign(&aws_lc_rs::rand::SystemRandom::new(), &signed)
            .unwrap();
        let mut verify_body = vec![4, 3];
        verify_body.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
        verify_body.extend_from_slice(signature.as_ref());
        let verify = quic_certificate_message(15, &verify_body);
        transcript.extend_from_slice(&verify);
        server_flight.extend_from_slice(&verify);
        let server_finished = quic_certificate_message(
            20,
            &quic_certificate_finished(&secrets.server_secret, &transcript),
        );
        transcript.extend_from_slice(&server_finished);
        server_flight.extend_from_slice(&server_finished);
        driver.feed(&server_flight);
        let QuicHandshakeOutput::Done {
            mut to_send,
            result,
        } = driver.progress().unwrap()
        else {
            panic!("valid server flight must complete QUIC TLS");
        };

        let expected_alps = alps.then(|| quic_certificate_message(8, &[0, 4, 0x44, 0xcd, 0, 0]));
        let expected_certificate =
            request_certificate.then(|| quic_certificate_message(11, &[0, 0, 0, 0]));
        if let Some(message) = &expected_alps {
            transcript.extend_from_slice(message);
        }
        if let Some(message) = &expected_certificate {
            transcript.extend_from_slice(message);
        }
        let expected_finished = quic_certificate_message(
            20,
            &quic_certificate_finished(&secrets.client_secret, &transcript),
        );
        let mut messages = Vec::new();
        while let Some(message) = take_next_handshake_message(&mut to_send).unwrap() {
            messages.push(message);
        }
        assert!(to_send.is_empty());
        QuicClientCertificateFlight {
            message_types: messages.iter().map(|message| message[0]).collect(),
            certificate_matches: messages.iter().find(|message| message[0] == 11)
                == expected_certificate.as_ref(),
            alps_matches: messages.iter().find(|message| message[0] == 8) == expected_alps.as_ref(),
            finished_matches: messages.iter().find(|message| message[0] == 20)
                == Some(&expected_finished),
            early_data_accepted: result.early_data_accepted,
        }
    }

    #[test]
    fn quic_client_certificate_output_includes_requested_certificate_before_finished() {
        let mut mismatches = Vec::new();
        for alps in [false, true] {
            let report = quic_client_certificate_flight(true, alps);
            let expected_types = if alps { vec![8, 11, 20] } else { vec![11, 20] };
            if report.message_types != expected_types
                || !report.certificate_matches
                || !report.alps_matches
                || !report.finished_matches
                || report.early_data_accepted
            {
                mismatches.push(format!("alps={alps}: {report:?}"));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn quic_client_certificate_output_without_request_preserves_alps_finished_order() {
        for alps in [false, true] {
            let report = quic_client_certificate_flight(false, alps);
            assert_eq!(
                report.message_types,
                if alps { vec![8, 20] } else { vec![20] }
            );
            assert!(report.certificate_matches, "{report:?}");
            assert!(report.alps_matches, "{report:?}");
            assert!(report.finished_matches, "{report:?}");
            assert!(!report.early_data_accepted, "{report:?}");
        }
    }

    const ALPS_TICKET_IDENTITY: &[u8] = b"alps-state-ticket";
    const ALPS_TICKET_LOCAL_A: &[u8] = &[6, 0x40, 0x40];
    const ALPS_TICKET_LOCAL_B: &[u8] = &[6, 0x40, 0x80];
    const ALPS_TICKET_PEER_PARAMS: &[u8] = &[0x0f, 0x00];

    fn alps_ticket_config(
        store: Arc<InMemorySessionStore>,
        settings: &[u8],
        code_point: u16,
    ) -> HandshakeConfig {
        let mut config = make_config_with_store(store);
        config.profile = crate::profile::presets::chrome_155_quic();
        config
            .profile
            .extensions
            .iter_mut()
            .find(|extension| matches!(extension.extension_type, 0x4469 | 0x44cd))
            .unwrap()
            .extension_type = code_point;
        config.alps_payload = Some(settings.to_vec());
        config
    }

    fn alps_ticket_begin_peer(
        driver: &mut QuicHandshakeDriver,
        client_hello: &[u8],
        select_psk: bool,
    ) -> (Vec<u8>, QuicTrafficSecrets) {
        use crate::crypto::kx::{generate_key_pair, KxGroup};
        let key = generate_key_pair(KxGroup::X25519).unwrap();
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
        extensions.extend_from_slice(&((4 + key.public_key.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&[0, 29]);
        extensions.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key.public_key);
        if select_psk {
            extensions.extend_from_slice(&[0, 41, 0, 2, 0, 0]);
        }
        let mut server_hello = hrr_message(&[], 0x1301, &extensions);
        server_hello[6..38].fill(0x55);
        let mut transcript = client_hello.to_vec();
        transcript.extend_from_slice(&server_hello);
        driver.feed(&server_hello);
        let QuicHandshakeOutput::HandshakeSecretsReady { secrets, .. } = driver.progress().unwrap()
        else {
            panic!("ALPS ticket peer ServerHello must install keys");
        };
        (transcript, secrets)
    }

    fn alps_ticket_ee(code_point: u16, settings: Option<&[u8]>, accept_early: bool) -> Vec<u8> {
        let mut extensions = vec![0, 16, 0, 5, 0, 3, 2, b'h', b'3', 0, 57];
        extensions.extend_from_slice(&(ALPS_TICKET_PEER_PARAMS.len() as u16).to_be_bytes());
        extensions.extend_from_slice(ALPS_TICKET_PEER_PARAMS);
        if let Some(settings) = settings {
            extensions.extend_from_slice(&code_point.to_be_bytes());
            extensions.extend_from_slice(&(settings.len() as u16).to_be_bytes());
            extensions.extend_from_slice(settings);
        }
        if accept_early {
            extensions.extend_from_slice(&[0, 42, 0, 0]);
        }
        let mut body = (extensions.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&extensions);
        quic_certificate_message(8, &body)
    }

    fn alps_ticket_client_ee(code_point: u16, settings: &[u8]) -> Vec<u8> {
        let mut body = ((settings.len() + 4) as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&code_point.to_be_bytes());
        body.extend_from_slice(&(settings.len() as u16).to_be_bytes());
        body.extend_from_slice(settings);
        quic_certificate_message(8, &body)
    }

    fn alps_ticket_finish_peer(
        driver: &mut QuicHandshakeDriver,
        mut transcript: Vec<u8>,
        secrets: &QuicTrafficSecrets,
        mut server_flight: Vec<u8>,
        expected_client_ee: Option<Vec<u8>>,
    ) -> Box<QuicHandshakeResult> {
        let server_finished = quic_certificate_message(
            20,
            &quic_certificate_finished(&secrets.server_secret, &transcript),
        );
        transcript.extend_from_slice(&server_finished);
        server_flight.extend_from_slice(&server_finished);
        driver.feed(&server_flight);
        let QuicHandshakeOutput::Done { to_send, result } = driver.progress().unwrap() else {
            panic!("ALPS ticket peer must reach driver completion");
        };
        let mut expected_output = Vec::new();
        if let Some(message) = expected_client_ee {
            transcript.extend_from_slice(&message);
            expected_output.extend_from_slice(&message);
        }
        expected_output.extend_from_slice(&quic_certificate_message(
            20,
            &quic_certificate_finished(&secrets.client_secret, &transcript),
        ));
        assert!(
            to_send == expected_output,
            "ALPS client flight must match independently hashed CEE/Finished bytes"
        );
        result
    }

    fn alps_ticket_store_from_full_handshake(code_point: u16) -> Arc<InMemorySessionStore> {
        alps_ticket_store_from_handshake(code_point, ALPS_TICKET_LOCAL_A, true)
    }

    fn alps_ticket_store_from_handshake(
        code_point: u16,
        local_settings: &[u8],
        negotiate_alps: bool,
    ) -> Arc<InMemorySessionStore> {
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let store = Arc::new(InMemorySessionStore::new());
        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["example.com".into()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        let anchor =
            crate::verify::certchain::parse_trust_anchor_from_der(certificate.der()).unwrap();
        let mut config = alps_ticket_config(store.clone(), local_settings, code_point);
        config.custom_ca_anchors = Some(Arc::new(vec![anchor]));
        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let hello = driver.start().unwrap();
        let offered = parse_raw_client_hello_extensions(&hello);
        assert!(!offered.iter().any(|(kind, _)| matches!(*kind, 41 | 42)));
        assert!(offered.iter().any(|(kind, _)| *kind == code_point));
        let (mut transcript, secrets) = alps_ticket_begin_peer(&mut driver, &hello, false);
        let server_settings = [6, 0x41, 0];
        let mut flight = alps_ticket_ee(
            code_point,
            negotiate_alps.then_some(server_settings.as_slice()),
            false,
        );
        let der = certificate.der().as_ref();
        let mut cert_body = vec![0];
        cert_body.extend_from_slice(&((der.len() + 5) as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(der);
        cert_body.extend_from_slice(&[0, 0]);
        flight.extend_from_slice(&quic_certificate_message(11, &cert_body));
        transcript.extend_from_slice(&flight);
        let mut signed = vec![0x20; 64];
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        signed.extend_from_slice(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &transcript).as_ref(),
        );
        let signer = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &signing_key.serialize_der(),
        )
        .unwrap();
        let signature = signer
            .sign(&aws_lc_rs::rand::SystemRandom::new(), &signed)
            .unwrap();
        let mut verify_body = vec![4, 3];
        verify_body.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
        verify_body.extend_from_slice(signature.as_ref());
        let verify = quic_certificate_message(15, &verify_body);
        transcript.extend_from_slice(&verify);
        flight.extend_from_slice(&verify);
        let result = alps_ticket_finish_peer(
            &mut driver,
            transcript,
            &secrets,
            flight,
            negotiate_alps.then(|| alps_ticket_client_ee(code_point, local_settings)),
        );
        assert!(!result.early_data_accepted);
        let context = result
            .session_ticket_ctx
            .as_ref()
            .expect("completed handshake ticket context");
        assert_eq!(
            context.alps,
            if negotiate_alps {
                AlpsSessionState::Negotiated {
                    client_settings: local_settings.to_vec(),
                    server_settings: server_settings.to_vec(),
                }
            } else {
                AlpsSessionState::NotNegotiated
            }
        );
        alps_ticket_store_context(context, &store);
        store
    }

    fn alps_ticket_store_context(context: &SessionTicketContext, store: &InMemorySessionStore) {
        let nonce = [1, 2, 3, 4];
        let mut ticket_body = 3600u32.to_be_bytes().to_vec();
        ticket_body.extend_from_slice(&17u32.to_be_bytes());
        ticket_body.push(nonce.len() as u8);
        ticket_body.extend_from_slice(&nonce);
        ticket_body.extend_from_slice(&(ALPS_TICKET_IDENTITY.len() as u16).to_be_bytes());
        ticket_body.extend_from_slice(ALPS_TICKET_IDENTITY);
        ticket_body.extend_from_slice(&[0, 8, 0, 42, 0, 4]);
        ticket_body.extend_from_slice(&u32::MAX.to_be_bytes());
        context.process_new_session_ticket(&quic_certificate_message(4, &ticket_body));
        let stored = store
            .take("example.com:443")
            .expect("NST-derived ticket must reach shared store");
        let expected_psk = crate::crypto::hkdf::hkdf_expand_label(
            HkdfAlgorithm::Sha256,
            &context.resumption_master_secret,
            "resumption",
            &nonce,
            32,
        )
        .unwrap();
        assert!(
            stored.resumption_psk == expected_psk,
            "ticket must derive from the actual first handshake"
        );
        assert_eq!(stored.max_early_data_size, u32::MAX);
        assert_eq!(stored.alps, context.alps);
        assert_eq!(
            stored.peer_transport_parameters.as_deref(),
            Some(ALPS_TICKET_PEER_PARAMS)
        );
        store.store("example.com:443", stored);
    }

    fn alps_ticket_assert_real_identity(hello: &[u8]) {
        let extensions = parse_raw_client_hello_extensions(hello);
        let (_, psk) = extensions
            .iter()
            .find(|(kind, _)| *kind == 41)
            .expect("1-RTT PSK resumption remains offered");
        let identity_len = u16::from_be_bytes([psk[2], psk[3]]) as usize;
        assert!(
            &psk[4..4 + identity_len] == ALPS_TICKET_IDENTITY,
            "resumption must use the first handshake's NST identity"
        );
    }

    #[test]
    fn alps_ticket_state_changed_settings_retain_psk_without_early_data() {
        let mut unexpected_offers = Vec::new();
        for code_point in [0x4469, 0x44cd] {
            let store = alps_ticket_store_from_full_handshake(code_point);
            let config = alps_ticket_config(store, ALPS_TICKET_LOCAL_B, code_point);
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            if parse_raw_client_hello_extensions(&hello)
                .iter()
                .any(|(kind, _)| *kind == 42)
            {
                unexpected_offers.push(format!(
                    "ALPS 0x{code_point:04x}: A->B still offered early_data"
                ));
            }
        }
        assert!(
            unexpected_offers.is_empty(),
            "{}",
            unexpected_offers.join("\n")
        );
    }

    #[test]
    fn alps_ticket_state_unchanged_settings_accept_without_fresh_alps_or_cee() {
        for code_point in [0x4469, 0x44cd] {
            let store = alps_ticket_store_from_full_handshake(code_point);
            let config = alps_ticket_config(store.clone(), ALPS_TICKET_LOCAL_A, code_point);
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            assert!(driver.early_data_offer().is_some());
            let (mut transcript, secrets) = alps_ticket_begin_peer(&mut driver, &hello, true);
            let flight = alps_ticket_ee(code_point, None, true);
            transcript.extend_from_slice(&flight);
            let result = alps_ticket_finish_peer(&mut driver, transcript, &secrets, flight, None);
            assert!(result.early_data_accepted);
            let context = result.session_ticket_ctx.as_ref().unwrap();
            assert_eq!(
                context.alps,
                AlpsSessionState::Negotiated {
                    client_settings: ALPS_TICKET_LOCAL_A.to_vec(),
                    server_settings: vec![6, 0x41, 0],
                }
            );
            alps_ticket_store_context(context, &store);
            let mut next = QuicHandshakeDriver::new(
                alps_ticket_config(store, ALPS_TICKET_LOCAL_B, code_point).into_quic(Vec::new()),
            );
            let hello = next.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            assert!(
                next.early_data_offer().is_none(),
                "resumed NST must retain inherited settings"
            );
        }
    }

    #[test]
    fn alps_ticket_state_rejected_early_data_renegotiates_current_settings() {
        for code_point in [0x4469, 0x44cd] {
            let store = alps_ticket_store_from_full_handshake(code_point);
            let config = alps_ticket_config(store, ALPS_TICKET_LOCAL_B, code_point);
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            let (mut transcript, secrets) = alps_ticket_begin_peer(&mut driver, &hello, true);
            let flight = alps_ticket_ee(code_point, Some(&[6, 0x42, 0]), false);
            transcript.extend_from_slice(&flight);
            let result = alps_ticket_finish_peer(
                &mut driver,
                transcript,
                &secrets,
                flight,
                Some(alps_ticket_client_ee(code_point, ALPS_TICKET_LOCAL_B)),
            );
            assert!(!result.early_data_accepted);
            assert_eq!(
                result.session_ticket_ctx.as_ref().unwrap().alps,
                AlpsSessionState::Negotiated {
                    client_settings: ALPS_TICKET_LOCAL_B.to_vec(),
                    server_settings: vec![6, 0x42, 0],
                }
            );
        }
    }

    #[test]
    fn alps_ticket_state_unknown_preserves_legacy_offer_and_inheritance() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_quic_early_data_ticket();
        ticket.max_early_data_size = u32::MAX;
        assert_eq!(ticket.alps, AlpsSessionState::Unknown);
        store.store("example.com:443", ticket);
        let config = alps_ticket_config(store.clone(), ALPS_TICKET_LOCAL_B, 0x44cd);
        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let hello = driver.start().unwrap();
        assert!(driver.early_data_offer().is_some());
        let (mut transcript, secrets) = alps_ticket_begin_peer(&mut driver, &hello, true);
        let flight = alps_ticket_ee(0x44cd, None, true);
        transcript.extend_from_slice(&flight);
        let result = alps_ticket_finish_peer(&mut driver, transcript, &secrets, flight, None);
        let context = result.session_ticket_ctx.as_ref().unwrap();
        assert!(result.early_data_accepted);
        assert_eq!(context.alps, AlpsSessionState::Unknown);
        alps_ticket_store_context(context, &store);
    }

    #[test]
    fn alps_ticket_state_not_negotiated_preserves_offer_despite_new_local_settings() {
        let store = alps_ticket_store_from_handshake(0x44cd, ALPS_TICKET_LOCAL_A, false);
        let config = alps_ticket_config(store.clone(), ALPS_TICKET_LOCAL_B, 0x44cd);
        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let hello = driver.start().unwrap();
        alps_ticket_assert_real_identity(&hello);
        assert!(driver.early_data_offer().is_some());
        let (mut transcript, secrets) = alps_ticket_begin_peer(&mut driver, &hello, true);
        let flight = alps_ticket_ee(0x44cd, None, true);
        transcript.extend_from_slice(&flight);
        let result = alps_ticket_finish_peer(&mut driver, transcript, &secrets, flight, None);
        let context = result.session_ticket_ctx.as_ref().unwrap();
        assert!(result.early_data_accepted);
        assert_eq!(context.alps, AlpsSessionState::NotNegotiated);
        alps_ticket_store_context(context, &store);
    }

    #[test]
    fn alps_ticket_state_disabled_or_unoffered_settings_remove_early_but_keep_psk() {
        use crate::profile::types::{ext_type, ExtensionSource};
        for case in 0..6 {
            let store = alps_ticket_store_from_full_handshake(0x44cd);
            let mut config = alps_ticket_config(store, ALPS_TICKET_LOCAL_A, 0x44cd);
            match case {
                0 => config.alps_payload = None,
                1 => config.alps_payload = Some(Vec::new()),
                2 => config.profile.alps_protocols = Some(vec!["h2".into()]),
                3 => config
                    .profile
                    .extensions
                    .retain(|extension| !matches!(extension.extension_type, 0x4469 | 0x44cd)),
                4 => {
                    config.alps_payload = Some(ALPS_TICKET_LOCAL_B.to_vec());
                    config
                        .profile
                        .extensions
                        .iter_mut()
                        .find(|extension| extension.extension_type == ext_type::EARLY_DATA)
                        .unwrap()
                        .source = ExtensionSource::RawBytes {
                        data: String::new(),
                    };
                }
                5 => {
                    config
                        .profile
                        .extensions
                        .iter_mut()
                        .find(|extension| extension.extension_type == 0x44cd)
                        .unwrap()
                        .source = ExtensionSource::RawBytes {
                        data: "0003026832".into(),
                    }
                }
                _ => unreachable!(),
            }
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            assert!(
                !parse_raw_client_hello_extensions(&hello)
                    .iter()
                    .any(|(kind, _)| *kind == ext_type::EARLY_DATA),
                "case={case}"
            );
            assert!(driver.early_data_offer().is_none(), "case={case}");
        }
    }

    #[test]
    fn alps_ticket_state_empty_payload_is_distinct_from_disabled_alps() {
        for enabled in [false, true] {
            let store = alps_ticket_store_from_handshake(0x44cd, &[], true);
            let mut config = alps_ticket_config(store, &[], 0x44cd);
            if !enabled {
                config.alps_payload = None;
            }
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            assert_eq!(driver.early_data_offer().is_some(), enabled);
        }
    }

    #[test]
    fn alps_ticket_state_matching_raw_protocol_and_changed_codepoint_remain_eligible() {
        use crate::profile::types::ExtensionSource;
        for (previous, current) in [(0x4469, 0x44cd), (0x44cd, 0x4469)] {
            let store = alps_ticket_store_from_full_handshake(previous);
            let mut config = alps_ticket_config(store, ALPS_TICKET_LOCAL_A, current);
            config.profile.alps_protocols = Some(vec!["h2".into()]);
            config
                .profile
                .extensions
                .iter_mut()
                .find(|extension| extension.extension_type == current)
                .unwrap()
                .source = ExtensionSource::RawBytes {
                data: "0003026833".into(),
            };
            let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
            let hello = driver.start().unwrap();
            alps_ticket_assert_real_identity(&hello);
            assert!(driver.early_data_offer().is_some());
            assert!(parse_raw_client_hello_extensions(&hello)
                .iter()
                .any(|(kind, data)| *kind == current && data == &[0, 3, 2, b'h', b'3']));
        }
    }

    /// TLS 1.2 ServerHello body carrying `record_size_limit`, wrapped as a
    /// handshake message.
    fn tls12_server_hello_with_record_size_limit(limit: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // server_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id_len
        body.extend_from_slice(&0xC02Fu16.to_be_bytes()); // ECDHE_RSA_AES128_GCM_SHA256
        body.push(0x00); // compression
        body.extend_from_slice(&6u16.to_be_bytes()); // extensions_length
        body.extend_from_slice(&[0x00, 0x1c, 0x00, 0x02]);
        body.extend_from_slice(&limit.to_be_bytes());

        let mut message = vec![crate::handshake::handshake_type::SERVER_HELLO];
        let body_len = body.len();
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn tls12_full_flight_installs_the_peer_record_size_limit_on_the_writer() {
        let mut driver = HandshakeDriver::new(make_config());

        let mut handshake =
            Tls12Handshake::new([7u8; 32], "example.com", VerificationPolicy::default());
        handshake.feed_client_hello(b"ch");
        handshake
            .process_handshake_record(&tls12_server_hello_with_record_size_limit(512))
            .expect("ServerHello with record_size_limit");
        assert_eq!(handshake.peer_record_size_limit(), Some(512));

        let flight = crate::handshake::tls12::Tls12ClientFlight {
            client_certificate: None,
            client_key_exchange: hs_msg(0x10, 0x01, 8),
            client_finished: hs_msg(crate::handshake::handshake_type::FINISHED, 0x02, 12),
            traffic_keys: Tls12TrafficKeys {
                cipher_suite:
                    crate::crypto::tls12_cipher::Tls12CipherSuite::EcdheRsaAes128GcmSha256,
                client_write_key: vec![0x11; 16],
                server_write_key: vec![0x22; 16],
                client_write_iv: vec![0x01, 0x02, 0x03, 0x04],
                server_write_iv: vec![0x05, 0x06, 0x07, 0x08],
                client_write_mac_key: Vec::new(),
                server_write_mac_key: Vec::new(),
            },
        };

        driver
            .finish_tls12_full(handshake, [7u8; 32], flight)
            .expect("TLS 1.2 client flight");

        assert_eq!(
            driver.writer.peer_record_size_limit(),
            Some(512),
            "the server's ServerHello limit must reach the record writer"
        );
    }

    /// The other direction of RFC 8449 §4: the limit *we* advertise has to reach
    /// the record reader, or an over-large inbound record is never caught.
    #[test]
    fn driver_arms_the_reader_with_the_limit_we_advertise() {
        let firefox = make_config();
        assert_eq!(
            firefox.profile.record_size_limit,
            Some(16385),
            "firefox_147 is the profile that advertises record_size_limit"
        );
        assert_eq!(
            HandshakeDriver::new(firefox).reader.own_record_size_limit(),
            Some(16385),
            "the ClientHello limit must reach the record reader that enforces it"
        );
    }

    #[test]
    fn driver_leaves_the_reader_unbounded_when_we_advertise_nothing() {
        let mut chrome = make_config();
        chrome.profile = crate::profile::presets::chrome_146();
        assert_eq!(
            chrome.profile.record_size_limit, None,
            "Chrome does not send record_size_limit"
        );
        assert_eq!(
            HandshakeDriver::new(chrome).reader.own_record_size_limit(),
            None,
            "advertising nothing must leave only the protocol maximum in force"
        );
    }
}
