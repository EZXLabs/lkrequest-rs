//! TLS 1.2 handshake state machine.
//!
//! Drives both full and abbreviated (session ticket resumption) TLS 1.2 flows:
//!
//! ## Full ECDHE handshake
//!
//! ```text
//! Client                                Server
//! ------                                ------
//! ClientHello          -------->
//!                                       ServerHello
//!                                       Certificate
//!                                       ServerKeyExchange (ECDHE)
//!                      <--------        ServerHelloDone
//! ClientKeyExchange    -------->
//! ChangeCipherSpec     -------->
//! Finished             -------->
//!                      <--------        ChangeCipherSpec
//!                      <--------        Finished
//! [Application Data]   <------->        [Application Data]
//! ```
//!
//! ## Abbreviated handshake (session ticket resumption, RFC 5077)
//!
//! ```text
//! Client                                Server
//! ------                                ------
//! ClientHello (ticket) -------->
//!                                       ServerHello
//!                                       [NewSessionTicket]
//!                      <--------        ChangeCipherSpec
//!                      <--------        Finished
//! ChangeCipherSpec     -------->
//! Finished             -------->
//! [Application Data]   <------->        [Application Data]
//! ```

use aws_lc_rs::digest;

use std::sync::Arc;

use crate::crypto::kx::{self, EphemeralKeyPair, KxGroup};
use crate::crypto::prf::{self, PrfAlgorithm};
use crate::crypto::tls12_cipher::{Tls12CipherSuite, Tls12KeyExchange};
use crate::error::{AlertDescription, Result, TlsError};
use crate::extensions::record_size_limit::parse_peer_record_size_limit;
use crate::handshake::handshake_type;
use crate::handshake::tls13::client_hello_extensions;
use crate::profile::types::ext_type;
use crate::verify::policy::VerificationPolicy;

// ---------------------------------------------------------------------------
// Transcript Hash (for TLS 1.2 Finished verify_data)
// ---------------------------------------------------------------------------

/// Running hash of all handshake messages (used for Finished computation).
struct TranscriptHash {
    context: digest::Context,
    #[allow(dead_code)]
    algorithm: PrfAlgorithm,
}

impl TranscriptHash {
    fn new(algorithm: PrfAlgorithm) -> Self {
        Self {
            context: digest::Context::new(Self::ring_algorithm(algorithm)),
            algorithm,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn current_hash(&self) -> Vec<u8> {
        self.context.clone().finish().as_ref().to_vec()
    }

    fn ring_algorithm(algo: PrfAlgorithm) -> &'static digest::Algorithm {
        match algo {
            PrfAlgorithm::Sha256 => &digest::SHA256,
            PrfAlgorithm::Sha384 => &digest::SHA384,
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Current state of a TLS 1.2 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12State {
    /// Waiting for ServerHello.
    WaitServerHello,
    /// Waiting for server Certificate (full handshake) or CCS (abbreviated).
    /// When we sent a session ticket, the server may either:
    /// - Accept: send NewSessionTicket + CCS + Finished (abbreviated)
    /// - Reject: send Certificate + SKE + SHD (full handshake)
    WaitCertificateOrAbbreviated,
    /// Waiting for server Certificate (full handshake, no resumption attempted).
    WaitCertificate,
    /// Waiting for ServerKeyExchange.
    WaitServerKeyExchange,
    /// Waiting for ServerHelloDone (or optional CertificateRequest).
    WaitServerHelloDone,
    /// Server flight complete; need to send ClientKeyExchange + CCS + Finished.
    SendClientKeyExchange,
    /// Waiting for server ChangeCipherSpec.
    WaitServerChangeCipherSpec,
    /// Waiting for server Finished.
    WaitServerFinished,
    /// Handshake complete.
    Connected,
}

/// Action the caller should take after processing a handshake record.
#[derive(Debug)]
pub enum Tls12HandshakeAction {
    /// Continue reading more handshake messages.
    ContinueReading,

    /// Full handshake: server flight is complete. The caller should:
    /// 1. Send `client_certificate` when present (plaintext)
    /// 2. Send the `client_key_exchange` (plaintext)
    /// 3. Send ChangeCipherSpec (plaintext)
    /// 4. Install the write keys from `traffic_keys`
    /// 5. Send `client_finished` (encrypted with client write key)
    /// 6. Read ChangeCipherSpec from server
    /// 7. Install the read keys from `traffic_keys`
    /// 8. Read server Finished (encrypted with server read key)
    SendClientFlight(Tls12ClientFlight),

    /// Abbreviated handshake: server Finished verified. The caller should:
    /// 1. Install write keys from `traffic_keys`
    /// 2. Send ChangeCipherSpec (plaintext)
    /// 3. Send `client_finished` (encrypted with client write key)
    SendAbbreviatedFlight(Tls12AbbreviatedFlight),

    /// Server Finished received. Handshake is complete.
    /// Install application traffic keys.
    Complete(Tls12TrafficKeys),
}

/// Data the client needs to send after the server flight (full handshake).
#[derive(Debug)]
pub struct Tls12ClientFlight {
    /// Empty Certificate handshake message when the server requested client
    /// authentication and no client certificate is configured.
    pub client_certificate: Option<Vec<u8>>,
    /// ClientKeyExchange handshake message bytes.
    pub client_key_exchange: Vec<u8>,
    /// Client Finished handshake message bytes (to be encrypted).
    pub client_finished: Vec<u8>,
    /// Traffic keys for record protection.
    pub traffic_keys: Tls12TrafficKeys,
}

/// Data the client needs to send after abbreviated handshake server flight.
///
/// In abbreviated handshake, the server sends CCS + Finished first.
/// After verifying server Finished, the client sends CCS + Finished.
/// No ClientKeyExchange is needed.
#[derive(Debug)]
pub struct Tls12AbbreviatedFlight {
    /// Client Finished handshake message bytes (to be encrypted).
    pub client_finished: Vec<u8>,
    /// Traffic keys for record protection.
    pub traffic_keys: Tls12TrafficKeys,
}

/// TLS 1.2 traffic keys (derived from the key block).
#[derive(Debug)]
pub struct Tls12TrafficKeys {
    /// The cipher suite negotiated.
    pub cipher_suite: Tls12CipherSuite,
    /// Client write key.
    pub client_write_key: Vec<u8>,
    /// Server write key.
    pub server_write_key: Vec<u8>,
    /// Client write IV.
    pub client_write_iv: Vec<u8>,
    /// Server write IV.
    pub server_write_iv: Vec<u8>,
    /// Client write MAC key (empty for AEAD suites).
    pub client_write_mac_key: Vec<u8>,
    /// Server write MAC key (empty for AEAD suites).
    pub server_write_mac_key: Vec<u8>,
}

impl Tls12TrafficKeys {
    /// Create a [`crate::record::Tls12RecordCipher`] from these traffic keys for the given role.
    ///
    /// `client_side`: `true` → uses `client_write_*` keys,
    ///                `false` → uses `server_write_*` keys.
    pub fn to_record_cipher(
        &self,
        client_side: bool,
    ) -> crate::error::Result<crate::record::Tls12RecordCipher> {
        let (key, iv, mac_key) = if client_side {
            (
                &self.client_write_key[..],
                &self.client_write_iv[..],
                &self.client_write_mac_key[..],
            )
        } else {
            (
                &self.server_write_key[..],
                &self.server_write_iv[..],
                &self.server_write_mac_key[..],
            )
        };
        create_tls12_record_cipher(&self.cipher_suite, key, iv, mac_key)
    }

    /// Install the client-side write keys on a [`crate::record::writer::RecordWriter`].
    pub fn install_on_writer(
        &self,
        writer: &mut crate::record::writer::RecordWriter,
    ) -> crate::error::Result<()> {
        writer.set_tls12_keys(self.to_record_cipher(true)?);
        Ok(())
    }

    /// Install the server-side write keys on a [`crate::record::reader::RecordReader`].
    pub fn install_on_reader(
        &self,
        reader: &mut crate::record::reader::RecordReader,
    ) -> crate::error::Result<()> {
        reader.set_tls12_keys(self.to_record_cipher(false)?);
        Ok(())
    }
}

/// Create a [`crate::record::Tls12RecordCipher`] from raw key material.
pub fn create_tls12_record_cipher(
    suite: &Tls12CipherSuite,
    key: &[u8],
    iv: &[u8],
    mac_key: &[u8],
) -> crate::error::Result<crate::record::Tls12RecordCipher> {
    use crate::crypto::tls12_cipher::{Tls12Chacha20Cipher, Tls12GcmCipher};
    use crate::error::TlsError;
    use crate::record::Tls12RecordCipher;

    match suite {
        Tls12CipherSuite::EcdheEcdsaChacha20Poly1305
        | Tls12CipherSuite::EcdheRsaChacha20Poly1305 => {
            if iv.len() != 12 {
                return Err(TlsError::CryptoError(format!(
                    "ChaCha20-Poly1305 IV must be 12 bytes, got {}",
                    iv.len()
                )));
            }
            if key.len() != 32 {
                return Err(TlsError::CryptoError(format!(
                    "ChaCha20-Poly1305 key must be 32 bytes, got {}",
                    key.len()
                )));
            }
            let iv_arr: [u8; 12] = iv.try_into().unwrap();
            let key_arr: [u8; 32] = key.try_into().unwrap();
            Ok(Tls12RecordCipher::Chacha20(Tls12Chacha20Cipher::new(
                &key_arr, &iv_arr,
            )?))
        }
        _ if suite.is_aead() => {
            if iv.len() != 4 {
                return Err(TlsError::CryptoError(format!(
                    "GCM implicit IV must be 4 bytes, got {}",
                    iv.len()
                )));
            }
            let iv_arr: [u8; 4] = iv.try_into().unwrap();
            let is_aes_256 = key.len() == 32;
            Ok(Tls12RecordCipher::Gcm(Tls12GcmCipher::new(
                key, &iv_arr, is_aes_256,
            )?))
        }
        _ if suite.is_cbc() => {
            use crate::crypto::tls12_cipher::{CbcMacAlgorithm, Tls12CbcCipher};

            let mac_algo = match suite {
                Tls12CipherSuite::EcdheRsaAes128CbcSha
                | Tls12CipherSuite::EcdheRsaAes256CbcSha
                | Tls12CipherSuite::RsaAes128CbcSha
                | Tls12CipherSuite::RsaAes256CbcSha => CbcMacAlgorithm::HmacSha1,
                Tls12CipherSuite::EcdheRsaAes128CbcSha256
                | Tls12CipherSuite::RsaAes128CbcSha256
                | Tls12CipherSuite::RsaAes256CbcSha256 => CbcMacAlgorithm::HmacSha256,
                Tls12CipherSuite::EcdheRsaAes256CbcSha384 => CbcMacAlgorithm::HmacSha384,
                _ => {
                    return Err(TlsError::CryptoError(format!(
                        "Unknown CBC MAC algorithm for suite {:?}",
                        suite
                    )))
                }
            };

            Ok(Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                key, mac_key, mac_algo,
            )))
        }
        _ => Err(TlsError::NotImplemented(format!(
            "Unsupported TLS 1.2 cipher suite: {:?}",
            suite
        ))),
    }
}

// ---------------------------------------------------------------------------
// TLS 1.2 Handshake state machine
// ---------------------------------------------------------------------------

/// TLS 1.2 handshake processor.
///
/// Processes incoming handshake records and produces actions for the caller.
pub struct Tls12Handshake {
    state: Tls12State,
    /// Transcript hash of all handshake messages.
    transcript: Option<TranscriptHash>,
    /// Raw ClientHello bytes — saved so we can re-hash if the cipher suite
    /// requires a different hash algorithm (e.g. SHA-384 instead of SHA-256).
    client_hello_bytes: Vec<u8>,
    /// Client random (from our ClientHello).
    client_random: [u8; 32],
    /// Server random (from ServerHello).
    server_random: [u8; 32],
    /// Negotiated cipher suite.
    cipher_suite: Option<Tls12CipherSuite>,
    /// PRF algorithm for this cipher suite.
    prf_algorithm: PrfAlgorithm,
    /// Server certificate DER bytes.
    server_certificates: Vec<Vec<u8>>,
    /// Whether the server requested a client certificate.
    client_certificate_requested: bool,
    /// ECDHE server key exchange parameters.
    server_kx_params: Option<ServerKxParams>,
    /// Our ephemeral key pair for ECDHE (consumed during key exchange).
    #[allow(dead_code)]
    key_pair: Option<EphemeralKeyPair>,
    /// Master secret (48 bytes).
    master_secret: Option<Vec<u8>>,
    /// Server hostname (for certificate verification).
    hostname: String,
    /// Certificate and signature verification policy.
    verification_policy: VerificationPolicy,
    /// Custom CA trust anchors (merged with Mozilla root store).
    custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,
    /// ALPN protocol negotiated in ServerHello extensions.
    negotiated_alpn: Option<String>,
    /// The server's RFC 8449 `record_size_limit`, from the ServerHello.
    ///
    /// TLS 1.3 carries this in EncryptedExtensions; RFC 8449 §4 restricts that
    /// placement to TLS 1.3, so under TLS 1.2 it rides in the ServerHello.
    /// It bounds the records we send, not the ones we receive.
    peer_record_size_limit: Option<u16>,
    /// Whether the server agreed to use extended master secret (RFC 7627).
    /// When true, master_secret is derived using the session hash (transcript)
    /// instead of client_random + server_random.
    use_extended_master_secret: bool,
    /// Master secret from a previous session ticket (for abbreviated handshake).
    /// When set, we attempt session resumption.
    resumed_master_secret: Option<Vec<u8>>,
    /// Whether the *original* session — the one the ticket in
    /// `resumed_master_secret` came from — used `extended_master_secret`.
    ///
    /// RFC 7627 §5.3 compares this against the ServerHello of the abbreviated
    /// handshake; see [`Tls12Handshake::check_abbreviated_extended_master_secret`].
    /// `None` means the ticket carries no record of it, in which case the
    /// comparison cannot be made.
    resumed_session_used_ems: Option<bool>,
    /// Whether the current handshake is abbreviated (session ticket resumption).
    abbreviated: bool,
    /// Named groups advertised in the `supported_groups` extension of the
    /// ClientHello we sent, read back off the bytes in `feed_client_hello`.
    ///
    /// RFC 8422 §5.4 lets the server pick the ECDHE curve, but only from this
    /// list. `None` means the ClientHello was not available or not parseable,
    /// so there is nothing to check against.
    offered_groups: Option<Vec<u16>>,
    /// Signature algorithms advertised in the ClientHello we sent.
    ///
    /// RFC 5246 §7.4.1.4.1 requires the ServerKeyExchange signature to use one
    /// of them. `None` means unknown (see `offered_groups`); an empty list means
    /// we sent no `signature_algorithms` extension, in which case the RFC's
    /// SHA-1 defaults apply.
    offered_signature_algorithms: Option<Vec<u16>>,
    /// Extension types actually emitted in the ClientHello we sent, plus the
    /// ones we signalled under a different code point (see RFC 5746 §3.4 and
    /// [`client_hello_offers_renegotiation_scsv`]).
    ///
    /// Read back off the wire bytes rather than off the profile for the same
    /// reason as the two lists above, and used for the same kind of check the
    /// TLS 1.3 path makes in `Tls13Handshake::check_server_hello_extensions`:
    /// RFC 5246 §7.4.1.4 forbids the server from answering with an extension
    /// we never offered.
    ///
    /// `None` means the ClientHello was not available or not parseable, in
    /// which case there is nothing to compare against and the
    /// unsolicited-extension check is skipped.
    offered_extensions: Option<Vec<u16>>,
}

/// The signature algorithms a server may assume when the ClientHello carried no
/// `signature_algorithms` extension (RFC 5246 §7.4.1.4.1): SHA-1 with each
/// certificate type the negotiated cipher suite can use.
const TLS12_DEFAULT_SIGNATURE_ALGORITHMS: [u16; 3] = [
    0x0201, // rsa_pkcs1_sha1
    0x0202, // dsa_sha1
    0x0203, // ecdsa_sha1
];

/// Parsed ServerKeyExchange parameters for ECDHE.
#[allow(dead_code)]
struct ServerKxParams {
    /// Named curve (e.g. 0x0017 = P-256, 0x001D = X25519).
    curve: u16,
    /// Server's ephemeral public key bytes.
    public_key: Vec<u8>,
    /// Signature algorithm (2 bytes).
    signature_algorithm: u16,
    /// Signature bytes.
    signature: Vec<u8>,
    /// The signed data: curve_type(1) + named_curve(2) + pubkey_len(1) + pubkey
    signed_params: Vec<u8>,
}

impl Tls12Handshake {
    /// Create a new TLS 1.2 handshake processor.
    ///
    /// `client_random` is the 32-byte random from the ClientHello we sent.
    /// `hostname` is the server name for certificate verification.
    pub fn new(
        client_random: [u8; 32],
        hostname: &str,
        verification_policy: VerificationPolicy,
    ) -> Self {
        Self {
            state: Tls12State::WaitServerHello,
            transcript: None,
            client_hello_bytes: Vec::new(),
            client_random,
            server_random: [0u8; 32],
            cipher_suite: None,
            prf_algorithm: PrfAlgorithm::Sha256,
            server_certificates: Vec::new(),
            client_certificate_requested: false,
            server_kx_params: None,
            key_pair: None,
            master_secret: None,
            hostname: hostname.to_string(),
            verification_policy,
            custom_ca_anchors: None,
            negotiated_alpn: None,
            peer_record_size_limit: None,
            use_extended_master_secret: false,
            resumed_master_secret: None,
            resumed_session_used_ems: None,
            abbreviated: false,
            offered_groups: None,
            offered_signature_algorithms: None,
            offered_extensions: None,
        }
    }

    /// Returns the ALPN protocol negotiated during the handshake (if any).
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    /// The server's RFC 8449 `record_size_limit`, if the ServerHello carried one.
    ///
    /// `None` means the extension was not negotiated and records are chunked at
    /// the protocol maximum, exactly as if RFC 8449 did not exist.
    pub fn peer_record_size_limit(&self) -> Option<u16> {
        self.peer_record_size_limit
    }

    /// Returns the master secret (if computed).
    pub fn master_secret(&self) -> Option<&[u8]> {
        self.master_secret.as_deref()
    }

    /// Returns the negotiated TLS 1.2 cipher suite (if ServerHello was processed).
    pub fn negotiated_cipher_suite(&self) -> Option<Tls12CipherSuite> {
        self.cipher_suite
    }

    /// The server's certificate chain (DER, leaf first) from the Certificate
    /// message. Empty on an abbreviated (resumption) handshake.
    pub fn server_certificates(&self) -> &[Vec<u8>] {
        &self.server_certificates
    }

    /// Whether the server agreed to `extended_master_secret` (RFC 7627) for
    /// the session established by this handshake.
    ///
    /// Whoever stores a session ticket issued on this connection must record
    /// this alongside it: RFC 7627 §5.4 — "they need to differentiate between
    /// sessions that use legacy and extended master secrets by adding a flag
    /// to the session state" — and §5.3's abbreviated-handshake checks are
    /// unrunnable without it. Feed it back in through
    /// [`Self::set_session_ticket_resumption`] on the resuming handshake.
    pub fn used_extended_master_secret(&self) -> bool {
        self.use_extended_master_secret
    }

    /// Set the master secret from a stored session ticket for resumption.
    ///
    /// When set, the handshake will attempt abbreviated handshake (RFC 5077).
    /// If the server rejects the ticket (sends Certificate instead of CCS),
    /// the handshake falls back to full handshake automatically.
    ///
    /// The ticket's `extended_master_secret` state is left unknown, which
    /// disables the RFC 7627 §5.3 checks for this handshake. Prefer
    /// [`Self::set_session_ticket_resumption`], which carries it.
    pub fn set_session_ticket_master_secret(&mut self, master_secret: Vec<u8>) {
        self.set_session_ticket_resumption(master_secret, None);
    }

    /// Set up session-ticket resumption, carrying the original session's
    /// `extended_master_secret` (RFC 7627) state along with its master secret.
    ///
    /// `original_used_extended_master_secret` is what
    /// [`Self::used_extended_master_secret`] reported on the handshake that
    /// issued the ticket. `None` means the stored ticket predates that
    /// bookkeeping; the handshake then proceeds exactly as before, with the
    /// §5.3 checks skipped, because assuming either answer would be wrong:
    /// assuming `false` would abort every resumption against the (near
    /// universal) servers that do negotiate EMS, and assuming `true` would
    /// abort every resumption of a legacy non-EMS session.
    pub fn set_session_ticket_resumption(
        &mut self,
        master_secret: Vec<u8>,
        original_used_extended_master_secret: Option<bool>,
    ) {
        self.resumed_master_secret = Some(master_secret);
        self.resumed_session_used_ems = original_used_extended_master_secret;
    }

    /// Set custom CA trust anchors (merged with Mozilla root store).
    pub fn set_custom_ca_anchors(
        &mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) {
        self.custom_ca_anchors = Some(anchors);
    }

    /// Whether the handshake is using abbreviated mode (session ticket resumption).
    ///
    /// Only valid after `process_server_hello()` has been called and the
    /// server accepted the session ticket.
    pub fn is_abbreviated(&self) -> bool {
        self.abbreviated
    }

    /// Feed the original ClientHello bytes into the transcript.
    ///
    /// Must be called before processing any server messages.
    /// The bytes are also saved so we can re-hash if the ServerHello
    /// selects a cipher suite that requires SHA-384 instead of SHA-256.
    pub fn feed_client_hello(&mut self, ch_bytes: &[u8]) {
        // We don't know the PRF algorithm yet (determined by ServerHello).
        // Start with SHA-256 as default, will reset if needed.
        self.client_hello_bytes = ch_bytes.to_vec();
        self.record_offer(ch_bytes);
        let mut t = TranscriptHash::new(PrfAlgorithm::Sha256);
        t.update(ch_bytes);
        self.transcript = Some(t);
    }

    /// Read the extension types, `supported_groups` and `signature_algorithms`
    /// we advertised back off the ClientHello bytes we sent.
    ///
    /// The offer is taken from the wire rather than from the profile so it stays
    /// exact under GREASE and extension permutation, and so the TLS 1.2 state
    /// machine does not need to carry a profile it otherwise has no use for.
    fn record_offer(&mut self, ch_bytes: &[u8]) {
        let Some(extensions) = client_hello_extensions(ch_bytes) else {
            // Not a parseable ClientHello (unit tests feed placeholder bytes);
            // there is nothing to compare a server's choice against.
            self.offered_groups = None;
            self.offered_signature_algorithms = None;
            self.offered_extensions = None;
            return;
        };
        let body = |target: u16| {
            extensions
                .iter()
                .find(|(extension_type, _)| *extension_type == target)
                .map(|(_, body)| *body)
        };

        // supported_groups: NamedGroupList<2..2^16-1> — a 2-byte length then
        // 2-byte code points (RFC 8422 §5.1.1). Absent means the client stated
        // no preference, so leave the check disabled rather than reject
        // everything.
        self.offered_groups = body(0x000a).and_then(parse_u16_list);

        // signature_algorithms has the same shape. When it is absent RFC 5246
        // §7.4.1.4.1 says the server must behave as if SHA-1 with each
        // certificate type had been offered — so accept exactly that.
        self.offered_signature_algorithms = Some(match body(0x000d) {
            Some(data) => parse_u16_list(data).unwrap_or_default(),
            None => TLS12_DEFAULT_SIGNATURE_ALGORITHMS.to_vec(),
        });

        // The extension types themselves, for RFC 5246 §7.4.1.4.
        let mut offered_extensions: Vec<u16> = extensions
            .iter()
            .map(|(extension_type, _)| *extension_type)
            .collect();

        // RFC 5746 §3.4 lets a client signal secure renegotiation with the
        // `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` cipher suite *instead of* the
        // `renegotiation_info` extension, and §3.6 then requires the server to
        // answer with the extension. That answer is solicited even though no
        // extension of that type went out, so fold the SCSV into the offer.
        // Every shipped profile sends the extension, so this only matters for a
        // profile that speaks the older dialect.
        if !offered_extensions.contains(&ext_type::RENEGOTIATION_INFO)
            && client_hello_offers_renegotiation_scsv(ch_bytes)
        {
            offered_extensions.push(ext_type::RENEGOTIATION_INFO);
        }
        self.offered_extensions = Some(offered_extensions);
    }

    /// Reject a ServerHello extension we never offered (RFC 5246 §7.4.1.4).
    ///
    /// Mirrors `Tls13Handshake::check_encrypted_extension_offered`: when the
    /// offer is unknown the check stays out of the way rather than rejecting
    /// everything.
    fn check_server_hello_extension_offered(&self, extension_type: u16) -> Result<()> {
        let Some(ref offered) = self.offered_extensions else {
            return Ok(());
        };
        if offered.contains(&extension_type) {
            return Ok(());
        }
        Err(TlsError::local_alert(
            AlertDescription::UnsupportedExtension,
            format!("server sent unsolicited ServerHello extension 0x{extension_type:04x}"),
        ))
    }

    /// Process an incoming handshake record.
    ///
    /// The `record` is the raw handshake payload (after record-layer decapsulation).
    /// For TLS 1.2, handshake messages before CCS are not encrypted.
    pub fn process_handshake_record(&mut self, record: &[u8]) -> Result<Tls12HandshakeAction> {
        let mut offset = 0;

        while offset < record.len() {
            if offset + 4 > record.len() {
                return Err(TlsError::HandshakeFailure(
                    "handshake message too short for header".into(),
                ));
            }

            let msg_type = record[offset];
            let msg_len = ((record[offset + 1] as usize) << 16)
                | ((record[offset + 2] as usize) << 8)
                | (record[offset + 3] as usize);

            if offset + 4 + msg_len > record.len() {
                return Err(TlsError::HandshakeFailure(format!(
                    "handshake message truncated: type={:#04x}, len={}, available={}",
                    msg_type,
                    msg_len,
                    record.len() - offset - 4
                )));
            }

            let msg_bytes = &record[offset..offset + 4 + msg_len];
            let msg_body = &record[offset + 4..offset + 4 + msg_len];

            let action = self.process_single_message(msg_type, msg_body, msg_bytes)?;

            offset += 4 + msg_len;

            // If an action needs to be returned, return it immediately.
            match action {
                Tls12HandshakeAction::ContinueReading => continue,
                other => return Ok(other),
            }
        }

        Ok(Tls12HandshakeAction::ContinueReading)
    }

    /// Process the server's Finished message (after CCS, so it's encrypted).
    ///
    /// The caller decrypts the record and passes the plaintext here.
    pub fn process_server_finished(
        &mut self,
        finished_body: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        if self.state != Tls12State::WaitServerFinished {
            return Err(TlsError::HandshakeFailure(format!(
                "unexpected server Finished in state {:?}",
                self.state
            )));
        }

        // Verify server Finished
        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("no master secret for Finished verification".into())
        })?;

        let transcript = self.transcript.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("no transcript for Finished verification".into())
        })?;

        let expected_verify_data = prf::compute_verify_data(
            self.prf_algorithm,
            master_secret,
            "server finished",
            &transcript.current_hash(),
        )?;

        // The finished_body should be: handshake_type(1) + length(3) + verify_data(12)
        // Or just the verify_data if already parsed.
        let verify_data =
            if finished_body.len() == 16 && finished_body[0] == handshake_type::FINISHED {
                // Full handshake message: type(1) + len(3) + verify_data(12)
                &finished_body[4..]
            } else if finished_body.len() == 12 {
                finished_body
            } else {
                return Err(TlsError::HandshakeFailure(format!(
                    "unexpected Finished length: {}",
                    finished_body.len()
                )));
            };

        if verify_data != expected_verify_data.as_slice() {
            return Err(TlsError::HandshakeFailure(
                "server Finished verify_data mismatch".into(),
            ));
        }

        tracing::debug!("TLS 1.2 server Finished verified successfully");
        self.state = Tls12State::Connected;

        // Return the traffic keys (already computed when sending client flight)
        let suite = self
            .cipher_suite
            .ok_or_else(|| TlsError::HandshakeFailure("no cipher suite".into()))?;

        // Re-derive keys for the complete action
        let ms = master_secret.clone();
        let kb = prf::expand_key_block(
            self.prf_algorithm,
            &ms,
            &self.server_random,
            &self.client_random,
            suite.mac_key_len(),
            suite.enc_key_len(),
            suite.fixed_iv_len(),
        )?;

        Ok(Tls12HandshakeAction::Complete(Tls12TrafficKeys {
            cipher_suite: suite,
            client_write_key: kb.client_write_key,
            server_write_key: kb.server_write_key,
            client_write_iv: kb.client_write_iv,
            server_write_iv: kb.server_write_iv,
            client_write_mac_key: kb.client_write_mac_key,
            server_write_mac_key: kb.server_write_mac_key,
        }))
    }

    /// Current handshake state.
    pub fn state(&self) -> Tls12State {
        self.state
    }

    /// Feed a raw handshake message into the transcript hash.
    ///
    /// Used for messages that arrive between our Client Finished and the
    /// server's CCS — typically NewSessionTicket (RFC 5077). These messages
    /// are not processed by the handshake state machine but must be included
    /// in the transcript for the server's Finished verification.
    pub fn feed_handshake_message(&mut self, msg_bytes: &[u8]) {
        if let Some(ref mut t) = self.transcript {
            t.update(msg_bytes);
        }
    }

    /// Notify the handshake that the server's ChangeCipherSpec has been received.
    ///
    /// Called by the connector after reading the CCS record (which is handled
    /// at the record layer, not the handshake layer).
    pub fn notify_server_ccs_received(&mut self) {
        if self.state == Tls12State::WaitServerChangeCipherSpec {
            self.state = Tls12State::WaitServerFinished;
        }
    }

    /// Accept the abbreviated handshake when CCS is received from the server.
    ///
    /// Called by the connector when it receives a CCS record while in the
    /// `WaitCertificateOrAbbreviated` state. This confirms that the server
    /// accepted our session ticket.
    ///
    /// Returns the traffic keys derived from the restored master secret.
    /// The connector should install read keys, then read + verify server Finished.
    pub fn accept_abbreviated_ccs(&mut self) -> Result<Tls12TrafficKeys> {
        if self.state != Tls12State::WaitCertificateOrAbbreviated {
            return Err(TlsError::HandshakeFailure(format!(
                "accept_abbreviated_ccs called in wrong state: {:?}",
                self.state
            )));
        }

        // The server has just committed to resuming (CCS with no Certificate),
        // so this is the moment RFC 7627 §5.3 describes as "a ServerHello that
        // accepts an abbreviated handshake". Check before any key derivation.
        self.check_abbreviated_extended_master_secret()?;

        let master_secret = self.resumed_master_secret.take().ok_or_else(|| {
            TlsError::HandshakeFailure("no resumed master_secret for abbreviated handshake".into())
        })?;

        let suite = self.cipher_suite.ok_or_else(|| {
            TlsError::HandshakeFailure("no cipher suite for abbreviated handshake".into())
        })?;

        // Derive key block from restored master_secret + new randoms
        let key_block = prf::expand_key_block(
            self.prf_algorithm,
            &master_secret,
            &self.server_random,
            &self.client_random,
            suite.mac_key_len(),
            suite.enc_key_len(),
            suite.fixed_iv_len(),
        )?;

        self.master_secret = Some(master_secret);
        self.abbreviated = true;
        self.state = Tls12State::WaitServerFinished;

        tracing::debug!(
            cipher = ?suite,
            "tls12.abbreviated_handshake_accepted",
        );

        Ok(Tls12TrafficKeys {
            cipher_suite: suite,
            client_write_key: key_block.client_write_key,
            server_write_key: key_block.server_write_key,
            client_write_iv: key_block.client_write_iv,
            server_write_iv: key_block.server_write_iv,
            client_write_mac_key: key_block.client_write_mac_key,
            server_write_mac_key: key_block.server_write_mac_key,
        })
    }

    /// RFC 7627 §5.3 — the client's half of the triple-handshake defence, run
    /// once the server has accepted an abbreviated (resumption) handshake.
    ///
    /// The RFC gives the client exactly two rules, and they point in opposite
    /// directions; both are `MUST abort`:
    ///
    /// - "If the original session did not use the `extended_master_secret`
    ///   extension but the new ServerHello contains the extension, the client
    ///   MUST abort the handshake." A server cannot upgrade a legacy session's
    ///   security by asserting EMS after the fact — the master secret being
    ///   resumed was still computed the old way, so the claim is either a bug
    ///   or an attacker splicing in a different session.
    ///
    /// - "If the original session used the extension but the new ServerHello
    ///   does not contain the extension, the client MUST abort the handshake."
    ///   This is the downgrade direction, and §5.4 closes the obvious escape
    ///   hatch: even though continuing "MAY be safe" because the original
    ///   session's extended master secret still protects it, "this document
    ///   recommends that the client and server MUST abort such handshakes".
    ///
    /// Matching state in either direction (both EMS, or neither) continues.
    ///
    /// The extension is a bare flag, so "the new ServerHello contains the
    /// extension" is [`Self::use_extended_master_secret`], set while parsing
    /// the ServerHello.
    ///
    /// Not implemented here: §5.3's *first* client rule, "the client SHOULD NOT
    /// offer an abbreviated handshake to resume a session that does not use an
    /// extended master secret". That one changes what the ClientHello puts on
    /// the wire, which this crate deliberately does not decide for itself.
    fn check_abbreviated_extended_master_secret(&self) -> Result<()> {
        let Some(original_used_ems) = self.resumed_session_used_ems else {
            tracing::debug!(
                "tls12.resumption_ems_state_unknown — RFC 7627 §5.3 checks skipped for this ticket"
            );
            return Ok(());
        };

        match (original_used_ems, self.use_extended_master_secret) {
            (false, true) => Err(TlsError::local_alert(
                AlertDescription::HandshakeFailure,
                "RFC 7627 §5.3: server accepted an abbreviated handshake with \
                 extended_master_secret, but the session being resumed was \
                 established without it",
            )),
            (true, false) => Err(TlsError::local_alert(
                AlertDescription::HandshakeFailure,
                "RFC 7627 §5.3: server accepted an abbreviated handshake without \
                 extended_master_secret, but the session being resumed was \
                 established with it",
            )),
            _ => Ok(()),
        }
    }

    /// Process the server's Finished in abbreviated handshake and compute
    /// the client Finished.
    ///
    /// Called after `accept_abbreviated_ccs()` + reading the encrypted server Finished.
    /// Returns the client Finished bytes and traffic keys for the connector to send.
    pub fn process_abbreviated_server_finished(
        &mut self,
        finished_body: &[u8],
    ) -> Result<Tls12AbbreviatedFlight> {
        if self.state != Tls12State::WaitServerFinished || !self.abbreviated {
            return Err(TlsError::HandshakeFailure(format!(
                "process_abbreviated_server_finished called in wrong state: {:?}, abbreviated={}",
                self.state, self.abbreviated
            )));
        }

        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("no master secret for abbreviated Finished".into())
        })?;

        let transcript = self.transcript.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("no transcript for abbreviated Finished".into())
        })?;

        // Verify server Finished
        let expected_verify_data = prf::compute_verify_data(
            self.prf_algorithm,
            master_secret,
            "server finished",
            &transcript.current_hash(),
        )?;

        let verify_data =
            if finished_body.len() == 16 && finished_body[0] == handshake_type::FINISHED {
                &finished_body[4..]
            } else if finished_body.len() == 12 {
                finished_body
            } else {
                return Err(TlsError::HandshakeFailure(format!(
                    "unexpected abbreviated Finished length: {}",
                    finished_body.len()
                )));
            };

        if verify_data != expected_verify_data.as_slice() {
            return Err(TlsError::HandshakeFailure(
                "server Finished verify_data mismatch (abbreviated)".into(),
            ));
        }

        tracing::debug!("tls12.abbreviated_server_finished_verified");

        // Feed server Finished into transcript for client Finished computation
        // (server Finished message = type(1) + len(3) + verify_data)
        let server_finished_msg = build_handshake_message(handshake_type::FINISHED, verify_data);
        if let Some(ref mut t) = self.transcript {
            t.update(&server_finished_msg);
        }

        // Compute client Finished
        let client_transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("no transcript for client Finished".into()))?
            .current_hash();

        let client_verify_data = prf::compute_verify_data(
            self.prf_algorithm,
            master_secret,
            "client finished",
            &client_transcript_hash,
        )?;

        let client_finished =
            build_handshake_message(handshake_type::FINISHED, &client_verify_data);

        self.state = Tls12State::Connected;

        // Re-derive keys for the flight
        let suite = self
            .cipher_suite
            .ok_or_else(|| TlsError::HandshakeFailure("no cipher suite".into()))?;

        let key_block = prf::expand_key_block(
            self.prf_algorithm,
            master_secret,
            &self.server_random,
            &self.client_random,
            suite.mac_key_len(),
            suite.enc_key_len(),
            suite.fixed_iv_len(),
        )?;

        Ok(Tls12AbbreviatedFlight {
            client_finished,
            traffic_keys: Tls12TrafficKeys {
                cipher_suite: suite,
                client_write_key: key_block.client_write_key,
                server_write_key: key_block.server_write_key,
                client_write_iv: key_block.client_write_iv,
                server_write_iv: key_block.server_write_iv,
                client_write_mac_key: key_block.client_write_mac_key,
                server_write_mac_key: key_block.server_write_mac_key,
            },
        })
    }

    // -----------------------------------------------------------------------
    // Internal message processing
    // -----------------------------------------------------------------------

    fn process_single_message(
        &mut self,
        msg_type: u8,
        body: &[u8],
        full_msg: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        match self.state {
            Tls12State::WaitServerHello => {
                if msg_type != handshake_type::SERVER_HELLO {
                    return Err(TlsError::HandshakeFailure(format!(
                        "expected ServerHello, got type {:#04x}",
                        msg_type
                    )));
                }
                self.process_server_hello(body, full_msg)
            }
            Tls12State::WaitCertificateOrAbbreviated => {
                if msg_type == handshake_type::CERTIFICATE {
                    // Server rejected our session ticket → fall back to full handshake
                    tracing::debug!("tls12.abbreviated_rejected — falling back to full handshake");
                    self.resumed_master_secret = None;
                    // The old session is out of the picture; the new one's EMS
                    // state is whatever this full handshake negotiates.
                    self.resumed_session_used_ems = None;
                    self.process_certificate(body, full_msg)
                } else if msg_type == 0x04 {
                    // NewSessionTicket — server accepted ticket and is issuing a new one.
                    // Feed into transcript and continue waiting for CCS.
                    if let Some(ref mut t) = self.transcript {
                        t.update(full_msg);
                    }
                    tracing::debug!(len = body.len(), "tls12.abbreviated_new_session_ticket",);
                    Ok(Tls12HandshakeAction::ContinueReading)
                } else {
                    Err(TlsError::HandshakeFailure(format!(
                        "expected Certificate or NewSessionTicket in abbreviated handshake, got type {:#04x}",
                        msg_type
                    )))
                }
            }
            Tls12State::WaitCertificate => {
                if msg_type != handshake_type::CERTIFICATE {
                    return Err(TlsError::HandshakeFailure(format!(
                        "expected Certificate, got type {:#04x}",
                        msg_type
                    )));
                }
                self.process_certificate(body, full_msg)
            }
            Tls12State::WaitServerKeyExchange => {
                if msg_type == 0x0C {
                    // ServerKeyExchange
                    self.process_server_key_exchange(body, full_msg)
                } else if msg_type == handshake_type::CERTIFICATE_STATUS {
                    // CertificateStatus (OCSP Stapling, RFC 6066 Section 8).
                    // Sent between Certificate and ServerKeyExchange when the
                    // server includes an OCSP staple response. We don't validate
                    // the staple but must include it in the transcript hash.
                    if let Some(ref mut t) = self.transcript {
                        t.update(full_msg);
                    }
                    tracing::debug!(
                        len = body.len(),
                        "tls12.certificate_status_received (OCSP staple)",
                    );
                    Ok(Tls12HandshakeAction::ContinueReading)
                } else if msg_type == 0x0E {
                    // ServerHelloDone without ServerKeyExchange — RSA key exchange
                    self.process_server_hello_done(body, full_msg)
                } else {
                    Err(TlsError::HandshakeFailure(format!(
                        "expected ServerKeyExchange or ServerHelloDone, got type {:#04x}",
                        msg_type
                    )))
                }
            }
            Tls12State::WaitServerHelloDone => {
                if msg_type == 0x0D {
                    // CertificateRequest — no client certificate is configured,
                    // so send an empty Certificate message in the client flight.
                    self.client_certificate_requested = true;
                    if let Some(ref mut t) = self.transcript {
                        t.update(full_msg);
                    }
                    tracing::debug!(
                        "tls12.certificate_request_received — will send empty client certificate"
                    );
                    Ok(Tls12HandshakeAction::ContinueReading)
                } else if msg_type == 0x0E {
                    // ServerHelloDone
                    self.process_server_hello_done(body, full_msg)
                } else {
                    Err(TlsError::HandshakeFailure(format!(
                        "expected ServerHelloDone, got type {:#04x}",
                        msg_type
                    )))
                }
            }
            _ => Err(TlsError::HandshakeFailure(format!(
                "unexpected handshake message type {:#04x} in state {:?}",
                msg_type, self.state
            ))),
        }
    }

    fn process_server_hello(
        &mut self,
        body: &[u8],
        full_msg: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        if body.len() < 38 {
            return Err(TlsError::HandshakeFailure("ServerHello too short".into()));
        }

        // server_version (2) + random (32) + session_id_len (1) + ...
        let _server_version = u16::from_be_bytes([body[0], body[1]]);
        self.server_random.copy_from_slice(&body[2..34]);

        let session_id_len = body[34] as usize;
        let offset = 35 + session_id_len;

        if offset + 3 > body.len() {
            return Err(TlsError::HandshakeFailure("ServerHello truncated".into()));
        }

        let cipher_suite_code = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let _compression_method = body[offset + 2];

        // Resolve cipher suite
        let suite = Tls12CipherSuite::from_code_point(cipher_suite_code).ok_or_else(|| {
            TlsError::HandshakeFailure(format!(
                "unsupported TLS 1.2 cipher suite: 0x{cipher_suite_code:04x}"
            ))
        })?;

        tracing::debug!(
            "TLS 1.2 ServerHello: cipher_suite=0x{:04x} ({:?})",
            cipher_suite_code,
            suite
        );

        self.cipher_suite = Some(suite);
        self.prf_algorithm = suite.prf_algorithm();

        // Parse extensions (if present) to extract ALPN, etc.
        let ext_start = offset + 3; // after cipher_suite(2) + compression(1)
        if ext_start + 2 <= body.len() {
            let extensions_len =
                u16::from_be_bytes([body[ext_start], body[ext_start + 1]]) as usize;
            let mut ext_offset = ext_start + 2;
            let ext_end = ext_offset + extensions_len;
            let mut seen_extensions: Vec<u16> = Vec::new();

            while ext_offset + 4 <= ext_end && ext_offset + 4 <= body.len() {
                let ext_type = u16::from_be_bytes([body[ext_offset], body[ext_offset + 1]]);
                let ext_len =
                    u16::from_be_bytes([body[ext_offset + 2], body[ext_offset + 3]]) as usize;
                ext_offset += 4;

                if ext_offset + ext_len > body.len() {
                    break;
                }

                // RFC 5246 §7.4.1.4: "There MUST NOT be more than one extension
                // of the same type." A duplicate is how a parser and a peer end
                // up disagreeing about which copy counted, so refuse it before
                // any copy is honoured.
                if seen_extensions.contains(&ext_type) {
                    return Err(TlsError::local_alert(
                        AlertDescription::IllegalParameter,
                        format!("duplicate ServerHello extension 0x{ext_type:04x}"),
                    ));
                }
                seen_extensions.push(ext_type);

                // RFC 5246 §7.4.1.4: "the extension type MUST NOT appear in the
                // extended server hello unless the same extension type appeared
                // in the corresponding client hello", and a client that sees one
                // MUST abort with `unsupported_extension`. Checked before the
                // extension is acted on, so an unsolicited `record_size_limit`
                // never gets to bound the records we send.
                self.check_server_hello_extension_offered(ext_type)?;

                // extended_master_secret extension (type 0x0017 = 23)
                if ext_type == 0x0017 {
                    tracing::debug!("TLS 1.2 server agreed to extended_master_secret (RFC 7627)");
                    self.use_extended_master_secret = true;
                }

                // record_size_limit extension (type 0x001c = 28, RFC 8449).
                // The server's receive limit bounds the records we send once
                // the cipher is installed; below 64 is a fatal
                // illegal_parameter, so this parse is allowed to fail.
                if ext_type == 0x001c {
                    let limit =
                        parse_peer_record_size_limit(&body[ext_offset..ext_offset + ext_len])?;
                    tracing::debug!("TLS 1.2 server record_size_limit: {limit}");
                    self.peer_record_size_limit = Some(limit);
                }

                // ALPN extension (type 0x0010)
                if ext_type == 0x0010 && ext_len >= 2 {
                    let alpn_data = &body[ext_offset..ext_offset + ext_len];
                    let alpn_list_len = u16::from_be_bytes([alpn_data[0], alpn_data[1]]) as usize;
                    if alpn_list_len > 0 && 2 < alpn_data.len() {
                        let proto_len = alpn_data[2] as usize;
                        if 3 + proto_len <= alpn_data.len() {
                            if let Ok(proto) = std::str::from_utf8(&alpn_data[3..3 + proto_len]) {
                                tracing::debug!("TLS 1.2 ALPN negotiated: {}", proto);
                                self.negotiated_alpn = Some(proto.to_string());
                            }
                        }
                    }
                }

                ext_offset += ext_len;
            }
        }

        // If the cipher suite requires SHA-384, re-create the transcript hash
        // with SHA-384 and re-feed the saved ClientHello + this ServerHello.
        if suite.prf_algorithm() != PrfAlgorithm::Sha256 {
            tracing::debug!(
                "TLS 1.2: cipher suite requires {:?}, restarting transcript hash",
                suite.prf_algorithm()
            );
            let mut new_transcript = TranscriptHash::new(suite.prf_algorithm());
            new_transcript.update(&self.client_hello_bytes);
            new_transcript.update(full_msg);
            self.transcript = Some(new_transcript);
        } else if let Some(ref mut t) = self.transcript {
            t.update(full_msg);
        }

        // If we have a stored master secret from a session ticket, attempt
        // abbreviated handshake. The server will either:
        // - Accept: send [NewSessionTicket] + CCS + Finished (no Certificate)
        // - Reject: send Certificate + SKE + SHD (full handshake)
        if self.resumed_master_secret.is_some() {
            self.state = Tls12State::WaitCertificateOrAbbreviated;
            tracing::debug!("tls12.attempting_abbreviated_handshake");
        } else {
            self.state = Tls12State::WaitCertificate;
        }
        Ok(Tls12HandshakeAction::ContinueReading)
    }

    fn process_certificate(
        &mut self,
        body: &[u8],
        full_msg: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        if body.len() < 3 {
            return Err(TlsError::HandshakeFailure(
                "Certificate message too short".into(),
            ));
        }

        let total_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | (body[2] as usize);
        let mut offset = 3;
        let mut certs = Vec::new();

        while offset < 3 + total_len {
            if offset + 3 > body.len() {
                break;
            }
            let cert_len = ((body[offset] as usize) << 16)
                | ((body[offset + 1] as usize) << 8)
                | (body[offset + 2] as usize);
            offset += 3;

            if offset + cert_len > body.len() {
                return Err(TlsError::HandshakeFailure("Certificate truncated".into()));
            }

            certs.push(body[offset..offset + cert_len].to_vec());
            offset += cert_len;
        }

        tracing::debug!("TLS 1.2 received {} certificate(s)", certs.len());

        if certs.is_empty() {
            return Err(TlsError::CertificateError(
                "server sent no certificates".into(),
            ));
        }

        // Verify the certificate chain
        self.verification_policy.verify_certificate_chain(
            &certs,
            &self.hostname,
            std::time::SystemTime::now(),
            self.custom_ca_anchors.as_deref().map(|v| v.as_slice()),
        )?;

        self.server_certificates = certs;

        if let Some(ref mut t) = self.transcript {
            t.update(full_msg);
        }

        let suite = self
            .cipher_suite
            .ok_or_else(|| TlsError::HandshakeFailure("no cipher suite".into()))?;

        if suite.key_exchange() == Tls12KeyExchange::Rsa {
            self.state = Tls12State::WaitServerHelloDone;
        } else {
            self.state = Tls12State::WaitServerKeyExchange;
        }
        Ok(Tls12HandshakeAction::ContinueReading)
    }

    fn process_server_key_exchange(
        &mut self,
        body: &[u8],
        full_msg: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        // Parse ECDHE ServerKeyExchange (RFC 4492 Section 5.4)
        // ECParameters:
        //   curve_type (1) = 0x03 (named_curve)
        //   named_curve (2)
        // ECPoint:
        //   length (1)
        //   point (variable)
        // Signature:
        //   signature_algorithm (2)
        //   signature_length (2)
        //   signature (variable)

        if body.len() < 5 {
            return Err(TlsError::HandshakeFailure(
                "ServerKeyExchange too short".into(),
            ));
        }

        let curve_type = body[0];
        if curve_type != 0x03 {
            return Err(TlsError::HandshakeFailure(format!(
                "unsupported curve type: 0x{curve_type:02x} (only named_curve supported)"
            )));
        }

        let named_curve = u16::from_be_bytes([body[1], body[2]]);

        // RFC 8422 §5.4: the server selects the curve, but only from the
        // client's `supported_groups`. Whether *we* implement the curve is a
        // separate question, asked later in `build_ecdhe_key_exchange`; a curve
        // we never advertised has to be refused even if we could do the math,
        // because completing a handshake on it contradicts the ClientHello the
        // server just saw.
        if let Some(ref offered) = self.offered_groups {
            if !offered.contains(&named_curve) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "server selected ECDHE curve 0x{named_curve:04x}, which the client did not offer"
                    ),
                ));
            }
        }

        let pubkey_len = body[3] as usize;

        if 4 + pubkey_len + 4 > body.len() {
            return Err(TlsError::HandshakeFailure(
                "ServerKeyExchange truncated".into(),
            ));
        }

        let public_key = body[4..4 + pubkey_len].to_vec();

        // The signed params = everything up to the signature
        let signed_params = body[..4 + pubkey_len].to_vec();

        let sig_offset = 4 + pubkey_len;
        let sig_algorithm = u16::from_be_bytes([body[sig_offset], body[sig_offset + 1]]);
        let sig_len = u16::from_be_bytes([body[sig_offset + 2], body[sig_offset + 3]]) as usize;

        if sig_offset + 4 + sig_len > body.len() {
            return Err(TlsError::HandshakeFailure(
                "ServerKeyExchange signature truncated".into(),
            ));
        }

        let signature = body[sig_offset + 4..sig_offset + 4 + sig_len].to_vec();

        // RFC 5246 §7.4.1.4.1: the server must sign with an algorithm the client
        // advertised in `signature_algorithms` (or, if the client sent none, one
        // of the SHA-1 defaults).
        if let Some(ref offered) = self.offered_signature_algorithms {
            if !offered.contains(&sig_algorithm) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "server signed ServerKeyExchange with algorithm                          0x{sig_algorithm:04x}, which the client did not offer"
                    ),
                ));
            }
        }

        tracing::debug!(
            "TLS 1.2 ServerKeyExchange: curve=0x{:04x}, pubkey_len={}, sig_algo=0x{:04x}",
            named_curve,
            pubkey_len,
            sig_algorithm
        );

        // Verify the signature over client_random + server_random + signed_params
        if !self.server_certificates.is_empty() {
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(&self.client_random);
            signed_data.extend_from_slice(&self.server_random);
            signed_data.extend_from_slice(&signed_params);

            self.verification_policy
                .verify_server_key_exchange_signature(
                    &self.server_certificates[0],
                    sig_algorithm,
                    &signed_data,
                    &signature,
                )?;
        }

        self.server_kx_params = Some(ServerKxParams {
            curve: named_curve,
            public_key,
            signature_algorithm: sig_algorithm,
            signature,
            signed_params,
        });

        if let Some(ref mut t) = self.transcript {
            t.update(full_msg);
        }

        self.state = Tls12State::WaitServerHelloDone;
        Ok(Tls12HandshakeAction::ContinueReading)
    }

    fn process_server_hello_done(
        &mut self,
        _body: &[u8],
        full_msg: &[u8],
    ) -> Result<Tls12HandshakeAction> {
        tracing::debug!("TLS 1.2 ServerHelloDone received");

        if let Some(ref mut t) = self.transcript {
            t.update(full_msg);
        }

        let suite = self
            .cipher_suite
            .ok_or_else(|| TlsError::HandshakeFailure("no cipher suite".into()))?;

        let (pre_master_secret, client_key_exchange) = match suite.key_exchange() {
            Tls12KeyExchange::Ecdhe => self.build_ecdhe_key_exchange()?,
            Tls12KeyExchange::Rsa => self.build_rsa_key_exchange()?,
        };

        let client_certificate = self
            .client_certificate_requested
            .then(|| build_handshake_message(handshake_type::CERTIFICATE, &[0, 0, 0]));
        if let Some(ref certificate) = client_certificate {
            if let Some(ref mut t) = self.transcript {
                t.update(certificate);
            }
        }

        // Feed CKE into transcript
        if let Some(ref mut t) = self.transcript {
            t.update(&client_key_exchange);
        }

        // Compute master secret
        let master_secret = if self.use_extended_master_secret {
            let session_hash = self
                .transcript
                .as_ref()
                .ok_or_else(|| {
                    TlsError::HandshakeFailure("no transcript for extended master secret".into())
                })?
                .current_hash();
            tracing::debug!(
                session_hash_len = session_hash.len(),
                "tls12.computing_extended_master_secret",
            );
            prf::compute_extended_master_secret(
                self.prf_algorithm,
                &pre_master_secret,
                &session_hash,
            )?
        } else {
            prf::compute_master_secret(
                self.prf_algorithm,
                &pre_master_secret,
                &self.client_random,
                &self.server_random,
            )?
        };

        // Derive key block
        let key_block = prf::expand_key_block(
            self.prf_algorithm,
            &master_secret,
            &self.server_random,
            &self.client_random,
            suite.mac_key_len(),
            suite.enc_key_len(),
            suite.fixed_iv_len(),
        )?;

        // Build client Finished
        let transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("no transcript".into()))?
            .current_hash();

        let verify_data = prf::compute_verify_data(
            self.prf_algorithm,
            &master_secret,
            "client finished",
            &transcript_hash,
        )?;

        let client_finished = build_handshake_message(handshake_type::FINISHED, &verify_data);

        // Feed client Finished into transcript (for server Finished verification)
        if let Some(ref mut t) = self.transcript {
            t.update(&client_finished);
        }

        self.master_secret = Some(master_secret);
        self.state = Tls12State::WaitServerChangeCipherSpec;

        Ok(Tls12HandshakeAction::SendClientFlight(Tls12ClientFlight {
            client_certificate,
            client_key_exchange,
            client_finished,
            traffic_keys: Tls12TrafficKeys {
                cipher_suite: suite,
                client_write_key: key_block.client_write_key,
                server_write_key: key_block.server_write_key,
                client_write_iv: key_block.client_write_iv,
                server_write_iv: key_block.server_write_iv,
                client_write_mac_key: key_block.client_write_mac_key,
                server_write_mac_key: key_block.server_write_mac_key,
            },
        }))
    }

    /// ECDHE key exchange: generate ephemeral key pair, compute shared secret.
    /// Returns (pre_master_secret, client_key_exchange_message).
    fn build_ecdhe_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let kx_params = self
            .server_kx_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("no ServerKeyExchange received".into()))?;

        let kx_group = KxGroup::from_code_point(kx_params.curve).ok_or_else(|| {
            TlsError::HandshakeFailure(format!(
                "unsupported ECDHE curve: 0x{:04x}",
                kx_params.curve
            ))
        })?;

        let key_pair = kx::generate_key_pair(kx_group)?;
        let our_public_key = key_pair.public_key.clone();
        let pre_master_secret = kx::compute_shared_secret(key_pair, &kx_params.public_key)?;

        let cke_body = {
            let mut buf = Vec::new();
            buf.push(our_public_key.len() as u8);
            buf.extend_from_slice(&our_public_key);
            buf
        };
        let client_key_exchange = build_handshake_message(0x10, &cke_body);

        Ok((pre_master_secret, client_key_exchange))
    }

    /// RSA key exchange: generate random pre-master secret, encrypt with server's
    /// RSA public key using RSAES-PKCS1-v1_5 (RFC 5246 Section 7.4.7.1).
    /// Returns (pre_master_secret, client_key_exchange_message).
    fn build_rsa_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.server_certificates.is_empty() {
            return Err(TlsError::HandshakeFailure(
                "no server certificate for RSA key exchange".into(),
            ));
        }

        // Build 48-byte pre_master_secret: version(2) + random(46)
        let mut pre_master_secret = vec![0u8; 48];
        pre_master_secret[0] = 0x03; // TLS 1.2 major
        pre_master_secret[1] = 0x03; // TLS 1.2 minor
        let rng = aws_lc_rs::rand::SystemRandom::new();
        aws_lc_rs::rand::SecureRandom::fill(&rng, &mut pre_master_secret[2..]).map_err(|_| {
            TlsError::CryptoError("failed to generate RSA pre_master_secret".into())
        })?;

        // Extract SPKI from server certificate and create RSA public key
        let spki = crate::verify::certchain::extract_spki_from_cert(&self.server_certificates[0])?;
        let pub_key = aws_lc_rs::rsa::PublicEncryptingKey::from_der(spki).map_err(|_| {
            TlsError::CryptoError("failed to parse RSA public key from certificate".into())
        })?;
        let pkcs1_key = aws_lc_rs::rsa::Pkcs1PublicEncryptingKey::new(pub_key)
            .map_err(|_| TlsError::CryptoError("failed to create PKCS1 encrypting key".into()))?;

        let mut encrypted = vec![0u8; pkcs1_key.ciphertext_size()];
        let encrypted = pkcs1_key
            .encrypt(&pre_master_secret, &mut encrypted)
            .map_err(|_| {
                TlsError::CryptoError("RSA PKCS1 encryption of pre_master_secret failed".into())
            })?;

        // RFC 5246 Section 7.4.7.1: ClientKeyExchange for RSA is length-prefixed
        let enc_len = encrypted.len();
        let mut cke_body = Vec::with_capacity(2 + enc_len);
        cke_body.push((enc_len >> 8) as u8);
        cke_body.push(enc_len as u8);
        cke_body.extend_from_slice(encrypted);
        let client_key_exchange = build_handshake_message(0x10, &cke_body);

        tracing::debug!(encrypted_len = enc_len, "tls12.rsa_key_exchange",);

        Ok((pre_master_secret, client_key_exchange))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a TLS `vector<2..2^16-2>` of 2-byte code points: a 2-byte byte-count
/// followed by that many bytes, read as big-endian `u16`s.
///
/// Shared by `supported_groups` (RFC 8422 §5.1.1) and `signature_algorithms`
/// (RFC 5246 §7.4.1.4.1), which have the same shape. Returns `None` on a
/// malformed body.
fn parse_u16_list(data: &[u8]) -> Option<Vec<u16>> {
    let byte_len = u16::from_be_bytes([*data.first()?, *data.get(1)?]) as usize;
    if !byte_len.is_multiple_of(2) {
        return None;
    }
    let items = data.get(2..2 + byte_len)?;
    let (pairs, _) = items.as_chunks::<2>();
    Some(pairs.iter().map(|pair| u16::from_be_bytes(*pair)).collect())
}

/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` — RFC 5746 §3.3. Not a cipher suite: a
/// signalling value carried in the ClientHello's cipher suite list.
const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

/// Whether the ClientHello we sent signalled secure renegotiation with the
/// SCSV rather than with the `renegotiation_info` extension (RFC 5746 §3.4).
///
/// The server answers either signal with the `renegotiation_info` *extension*
/// (§3.6), so a ServerHello carrying it is solicited in both cases.
///
/// Returns `false` for anything that is not a parseable ClientHello — the
/// caller has already given up on the offer by that point.
fn client_hello_offers_renegotiation_scsv(ch_bytes: &[u8]) -> bool {
    // Handshake header (4) + legacy_version (2) + random (32) = the `body`
    // offsets that `client_hello_extensions` uses.
    let Some(body) = ch_bytes.get(4..) else {
        return false;
    };
    let Some(&session_id_len) = body.get(34) else {
        return false;
    };
    // `cipher_suites` is a 2-byte-length-prefixed list of 2-byte code points,
    // exactly the shape `parse_u16_list` reads.
    let Some(cipher_suites) = body.get(35 + session_id_len as usize..) else {
        return false;
    };
    parse_u16_list(cipher_suites)
        .is_some_and(|suites| suites.contains(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
}

/// Build a TLS handshake message: type(1) + length(3) + body.
fn build_handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut msg = Vec::with_capacity(4 + len);
    msg.push(msg_type);
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- build_handshake_message -----------------------------------------------

    #[test]
    fn build_handshake_message_basic() {
        let msg = build_handshake_message(0x0B, &[0x01, 0x02, 0x03]);
        assert_eq!(msg[0], 0x0B); // type
        assert_eq!(&msg[1..4], &[0x00, 0x00, 0x03]); // length = 3
        assert_eq!(&msg[4..], &[0x01, 0x02, 0x03]); // body
    }

    #[test]
    fn build_handshake_message_empty_body() {
        let msg = build_handshake_message(0x14, &[]);
        assert_eq!(msg.len(), 4);
        assert_eq!(msg[0], 0x14);
        assert_eq!(&msg[1..4], &[0x00, 0x00, 0x00]);
    }

    #[test]
    fn build_handshake_message_large_body() {
        let body = vec![0xAA; 300];
        let msg = build_handshake_message(0x01, &body);
        assert_eq!(msg.len(), 4 + 300);
        // length = 300 = 0x00012C
        assert_eq!(&msg[1..4], &[0x00, 0x01, 0x2C]);
    }

    // -- Tls12State -----------------------------------------------------------

    #[test]
    fn tls12_state_initial() {
        let hs = Tls12Handshake::new([0u8; 32], "example.com", VerificationPolicy::Insecure);
        assert_eq!(hs.state(), Tls12State::WaitServerHello);
    }

    // -- Tls12CipherSuite integration -----------------------------------------

    #[test]
    fn cipher_suite_from_code_point_aes128_gcm() {
        let suite = Tls12CipherSuite::from_code_point(0xC02F);
        assert!(suite.is_some());
    }

    #[test]
    fn cipher_suite_from_code_point_unknown() {
        let suite = Tls12CipherSuite::from_code_point(0xFFFF);
        assert!(suite.is_none());
    }

    // ========================================================================
    // TranscriptHash
    // ========================================================================

    #[test]
    fn transcript_hash_sha256_matches_ring() {
        let mut th = TranscriptHash::new(PrfAlgorithm::Sha256);
        th.update(b"hello");
        let hash = th.current_hash();
        let expected = digest::digest(&digest::SHA256, b"hello");
        assert_eq!(hash, expected.as_ref());
    }

    #[test]
    fn transcript_hash_sha384_matches_ring() {
        let mut th = TranscriptHash::new(PrfAlgorithm::Sha384);
        th.update(b"hello");
        let hash = th.current_hash();
        let expected = digest::digest(&digest::SHA384, b"hello");
        assert_eq!(hash, expected.as_ref());
    }

    #[test]
    fn transcript_hash_sha256_length() {
        let th = TranscriptHash::new(PrfAlgorithm::Sha256);
        assert_eq!(th.current_hash().len(), 32);
    }

    #[test]
    fn transcript_hash_sha384_length() {
        let th = TranscriptHash::new(PrfAlgorithm::Sha384);
        assert_eq!(th.current_hash().len(), 48);
    }

    #[test]
    fn transcript_hash_incremental_update() {
        let mut th = TranscriptHash::new(PrfAlgorithm::Sha256);
        th.update(b"hel");
        th.update(b"lo");
        let hash = th.current_hash();
        let expected = digest::digest(&digest::SHA256, b"hello");
        assert_eq!(hash, expected.as_ref());
    }

    #[test]
    fn transcript_hash_current_hash_is_snapshot() {
        let mut th = TranscriptHash::new(PrfAlgorithm::Sha256);
        th.update(b"first");
        let snap1 = th.current_hash();
        th.update(b"second");
        let snap2 = th.current_hash();
        assert_ne!(snap1, snap2);
    }

    #[test]
    fn transcript_ring_algorithm_sha256() {
        let algo = TranscriptHash::ring_algorithm(PrfAlgorithm::Sha256);
        assert_eq!(algo, &digest::SHA256);
    }

    #[test]
    fn transcript_ring_algorithm_sha384() {
        let algo = TranscriptHash::ring_algorithm(PrfAlgorithm::Sha384);
        assert_eq!(algo, &digest::SHA384);
    }

    // ========================================================================
    // Test helpers — message construction
    // ========================================================================

    fn make_server_hello_body(cipher_suite: u16, server_random: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // server_version = TLS 1.2
        body.extend_from_slice(server_random);
        body.push(0x00); // session_id_len = 0
        body.push((cipher_suite >> 8) as u8);
        body.push(cipher_suite as u8);
        body.push(0x00); // compression_method = none
        body
    }

    fn make_server_hello_body_with_alpn(
        cipher_suite: u16,
        server_random: &[u8; 32],
        alpn: &str,
    ) -> Vec<u8> {
        let mut body = make_server_hello_body(cipher_suite, server_random);
        // ALPN extension: type=0x0010, len= ...
        let proto_bytes = alpn.as_bytes();
        let alpn_list_len = 1 + proto_bytes.len(); // proto_len(1) + proto
        let ext_data_len = 2 + alpn_list_len; // alpn_list_len field(2) + list
        let ext_total_len = 4 + ext_data_len; // ext_type(2) + ext_len(2) + data
                                              // extensions_length
        body.push((ext_total_len >> 8) as u8);
        body.push(ext_total_len as u8);
        // ext_type = 0x0010 (ALPN)
        body.extend_from_slice(&[0x00, 0x10]);
        // ext_len
        body.push((ext_data_len >> 8) as u8);
        body.push(ext_data_len as u8);
        // alpn_list_len
        body.push((alpn_list_len >> 8) as u8);
        body.push(alpn_list_len as u8);
        // proto_len + proto
        body.push(proto_bytes.len() as u8);
        body.extend_from_slice(proto_bytes);
        body
    }

    fn make_server_hello_body_with_ems(cipher_suite: u16, server_random: &[u8; 32]) -> Vec<u8> {
        let mut body = make_server_hello_body(cipher_suite, server_random);
        // extended_master_secret extension: type=0x0017, len=0
        let ext_total_len = 4; // ext_type(2) + ext_len(2)
        body.push((ext_total_len >> 8) as u8);
        body.push(ext_total_len as u8);
        body.extend_from_slice(&[0x00, 0x17]); // ext_type
        body.extend_from_slice(&[0x00, 0x00]); // ext_len = 0
        body
    }

    fn make_server_hello_body_with_record_size_limit(
        cipher_suite: u16,
        server_random: &[u8; 32],
        limit: u16,
    ) -> Vec<u8> {
        let mut body = make_server_hello_body(cipher_suite, server_random);
        // record_size_limit extension: type=0x001c, len=2, value
        let ext_total_len = 4 + 2usize;
        body.push((ext_total_len >> 8) as u8);
        body.push(ext_total_len as u8);
        body.extend_from_slice(&[0x00, 0x1c]); // ext_type
        body.extend_from_slice(&[0x00, 0x02]); // ext_len = 2
        body.extend_from_slice(&limit.to_be_bytes());
        body
    }

    fn make_certificate_body(cert_ders: &[&[u8]]) -> Vec<u8> {
        let mut certs_buf = Vec::new();
        for cert in cert_ders {
            let len = cert.len();
            certs_buf.push((len >> 16) as u8);
            certs_buf.push((len >> 8) as u8);
            certs_buf.push(len as u8);
            certs_buf.extend_from_slice(cert);
        }
        let total = certs_buf.len();
        let mut body = Vec::new();
        body.push((total >> 16) as u8);
        body.push((total >> 8) as u8);
        body.push(total as u8);
        body.extend(certs_buf);
        body
    }

    fn make_ske_body(server_pub_key: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x03); // curve_type = named_curve
        body.extend_from_slice(&[0x00, 0x17]); // named_curve = P-256
        body.push(server_pub_key.len() as u8);
        body.extend_from_slice(server_pub_key);
        // Dummy signature (Insecure policy skips verification)
        body.extend_from_slice(&[0x04, 0x03]); // sig_algo = ecdsa_secp256r1_sha256
        let dummy_sig = [0u8; 8];
        body.push(0x00);
        body.push(dummy_sig.len() as u8);
        body.extend_from_slice(&dummy_sig);
        body
    }

    /// A ServerKeyExchange naming a specific curve and signature algorithm.
    fn make_ske_body_with(curve: u16, sig_algorithm: u16, server_pub_key: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x03); // curve_type = named_curve
        body.extend_from_slice(&curve.to_be_bytes());
        body.push(server_pub_key.len() as u8);
        body.extend_from_slice(server_pub_key);
        body.extend_from_slice(&sig_algorithm.to_be_bytes());
        let dummy_sig = [0u8; 8];
        body.extend_from_slice(&(dummy_sig.len() as u16).to_be_bytes());
        body.extend_from_slice(&dummy_sig);
        body
    }

    /// Drive a handshake to `WaitServerKeyExchange` having sent a *real*
    /// ClientHello built from `profile`, so the recorded offer is the genuine
    /// `supported_groups` / `signature_algorithms` that went on the wire.
    fn handshake_awaiting_ske(profile: &crate::profile::types::TlsProfile) -> Tls12Handshake {
        let client_hello =
            crate::handshake::client_hello::ClientHelloBuilder::new(profile, "test.example.com")
                .build()
                .expect("build ClientHello")
                .message;

        let mut hs = Tls12Handshake::new(
            [0x42u8; 32],
            "test.example.com",
            VerificationPolicy::Insecure,
        );
        hs.feed_client_hello(&client_hello);

        let sh_body = make_server_hello_body(0xC02F, &[0x11u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .expect("ServerHello");

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .expect("Certificate");

        assert_eq!(hs.state(), Tls12State::WaitServerKeyExchange);
        hs
    }

    /// chrome_150 narrowed to two groups, so that P-384 — a curve the engine
    /// fully implements — is one we did *not* offer. Only the local copy is
    /// touched; the shipped profile is untouched and nothing about what a real
    /// handshake advertises changes.
    fn profile_offering_x25519_and_p256() -> crate::profile::types::TlsProfile {
        let mut profile = crate::profile::presets::chrome_150();
        profile.supported_groups = vec![0x001d, 0x0017];
        profile.key_share_curves = vec![0x001d];
        profile
    }

    // ========================================================================
    // RFC 8422 §5.4 — the server must pick a curve we offered
    // ========================================================================

    #[test]
    fn ske_rejects_curve_the_client_did_not_offer() {
        let profile = profile_offering_x25519_and_p256();
        let mut hs = handshake_awaiting_ske(&profile);

        // P-384 is implemented by the engine but absent from this offer.
        let ske = make_ske_body_with(0x0018, 0x0403, &[0x04; 97]);
        let error = hs
            .process_handshake_record(&build_handshake_message(0x0C, &ske))
            .expect_err("a curve outside supported_groups must abort the handshake");

        assert!(
            error.to_string().contains("0x0018") && error.to_string().contains("did not offer"),
            "expected a not-offered curve rejection, got: {error}"
        );
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::IllegalParameter),
        );
    }

    #[test]
    fn ske_accepts_curve_the_client_offered() {
        let profile = profile_offering_x25519_and_p256();
        let mut hs = handshake_awaiting_ske(&profile);

        let ske = make_ske_body_with(0x0017, 0x0403, &generate_p256_public_key());
        let action = hs
            .process_handshake_record(&build_handshake_message(0x0C, &ske))
            .expect("an offered curve must be accepted");

        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);
    }

    // ========================================================================
    // RFC 5246 §7.4.1.4.1 — the server must sign with an algorithm we offered
    // ========================================================================

    #[test]
    fn ske_rejects_signature_algorithm_the_client_did_not_offer() {
        let profile = crate::profile::presets::chrome_150();
        assert!(
            !profile.signature_algorithms.contains(&0x0203),
            "the fixture depends on ecdsa_sha1 being absent from the offer"
        );
        let mut hs = handshake_awaiting_ske(&profile);

        let ske = make_ske_body_with(0x0017, 0x0203, &generate_p256_public_key());
        let error = hs
            .process_handshake_record(&build_handshake_message(0x0C, &ske))
            .expect_err("a signature algorithm outside signature_algorithms must abort");

        assert!(
            error.to_string().contains("0x0203") && error.to_string().contains("did not offer"),
            "expected a not-offered signature algorithm rejection, got: {error}"
        );
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::IllegalParameter),
        );
    }

    #[test]
    fn ske_accepts_signature_algorithm_the_client_offered() {
        let profile = crate::profile::presets::chrome_150();
        let offered = profile.signature_algorithms[0];
        let mut hs = handshake_awaiting_ske(&profile);

        let ske = make_ske_body_with(0x0017, offered, &generate_p256_public_key());
        let action = hs
            .process_handshake_record(&build_handshake_message(0x0C, &ske))
            .expect("an offered signature algorithm must be accepted");

        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);
    }

    #[test]
    fn real_client_hello_offer_is_read_back_off_the_wire_bytes() {
        let profile = profile_offering_x25519_and_p256();
        let hs = handshake_awaiting_ske(&profile);

        let groups = hs
            .offered_groups
            .clone()
            .expect("supported_groups recorded");
        assert!(groups.contains(&0x001d) && groups.contains(&0x0017));
        assert!(
            !groups.contains(&0x0018),
            "P-384 was not offered, so it must not appear in the recorded offer"
        );

        let sig_algs = hs
            .offered_signature_algorithms
            .clone()
            .expect("signature_algorithms recorded");
        assert_eq!(sig_algs, profile.signature_algorithms);
    }

    #[test]
    fn unparseable_client_hello_leaves_the_offer_unknown() {
        // The placeholder ClientHello the older unit tests feed is not a real
        // one; with no offer to compare against the checks stay out of the way
        // rather than rejecting everything.
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"fake-client-hello");
        assert!(hs.offered_groups.is_none());
        assert!(hs.offered_signature_algorithms.is_none());
        assert!(
            hs.offered_extensions.is_none(),
            "with no readable offer the unsolicited-extension check must stay disabled"
        );
    }

    // ========================================================================
    // RFC 5246 §7.4.1.4 — the server must not answer with an extension we
    // never offered, and must not send the same one twice
    // ========================================================================

    /// A handshake that has sent a *real* ClientHello built from `profile`, so
    /// the recorded offer is the genuine extension set that went on the wire.
    fn handshake_after_real_client_hello(
        profile: &crate::profile::types::TlsProfile,
    ) -> Tls12Handshake {
        let client_hello =
            crate::handshake::client_hello::ClientHelloBuilder::new(profile, "test.example.com")
                .build()
                .expect("build ClientHello")
                .message;

        let mut hs = Tls12Handshake::new(
            [0x42u8; 32],
            "test.example.com",
            VerificationPolicy::Insecure,
        );
        hs.feed_client_hello(&client_hello);
        hs
    }

    /// A ServerHello carrying an arbitrary extension block, so a test can send
    /// one we did not offer, or the same one twice.
    fn make_server_hello_body_with_extensions(
        cipher_suite: u16,
        server_random: &[u8; 32],
        extensions: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut block = Vec::new();
        for (extension_type, extension_body) in extensions {
            block.extend_from_slice(&extension_type.to_be_bytes());
            block.extend_from_slice(&(extension_body.len() as u16).to_be_bytes());
            block.extend_from_slice(extension_body);
        }
        let mut body = make_server_hello_body(cipher_suite, server_random);
        body.extend_from_slice(&(block.len() as u16).to_be_bytes());
        body.extend_from_slice(&block);
        body
    }

    /// An ALPN ServerHello extension body naming a single protocol.
    fn alpn_extension_body(protocol: &str) -> Vec<u8> {
        let mut body = vec![0x00, (1 + protocol.len()) as u8];
        body.push(protocol.len() as u8);
        body.extend_from_slice(protocol.as_bytes());
        body
    }

    fn feed_server_hello(hs: &mut Tls12Handshake, body: &[u8]) -> Result<Tls12HandshakeAction> {
        hs.process_handshake_record(&build_handshake_message(handshake_type::SERVER_HELLO, body))
    }

    #[test]
    fn server_hello_rejects_an_extension_the_client_did_not_offer() {
        let profile = crate::profile::presets::chrome_150();
        assert!(
            !profile
                .extensions
                .iter()
                .any(|spec| spec.extension_type == ext_type::RECORD_SIZE_LIMIT),
            "the fixture depends on record_size_limit being absent from the offer"
        );
        let mut hs = handshake_after_real_client_hello(&profile);

        let sh = make_server_hello_body_with_extensions(
            0xC02F,
            &[0x11u8; 32],
            &[(ext_type::RECORD_SIZE_LIMIT, 512u16.to_be_bytes().to_vec())],
        );
        let error =
            feed_server_hello(&mut hs, &sh).expect_err("an unsolicited extension must abort");

        assert!(
            error.to_string().contains("0x001c") && error.to_string().contains("unsolicited"),
            "expected an unsolicited-extension rejection, got: {error}"
        );
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::UnsupportedExtension),
        );
        assert!(
            hs.peer_record_size_limit().is_none(),
            "an extension we never offered must not bound the records we send"
        );
    }

    #[test]
    fn server_hello_accepts_the_extensions_the_client_offered() {
        let profile = crate::profile::presets::chrome_150();
        let mut hs = handshake_after_real_client_hello(&profile);

        let sh = make_server_hello_body_with_extensions(
            0xC02F,
            &[0x11u8; 32],
            &[
                (ext_type::EXTENDED_MASTER_SECRET, Vec::new()),
                (ext_type::ALPN, alpn_extension_body("h2")),
                (ext_type::RENEGOTIATION_INFO, vec![0x00]),
            ],
        );
        feed_server_hello(&mut hs, &sh).expect("extensions we offered must still be accepted");

        assert!(hs.use_extended_master_secret);
        assert_eq!(hs.negotiated_alpn(), Some("h2"));
        assert_eq!(hs.state(), Tls12State::WaitCertificate);
    }

    #[test]
    fn server_hello_rejects_a_duplicate_extension() {
        let profile = crate::profile::presets::chrome_150();
        let mut hs = handshake_after_real_client_hello(&profile);

        // Both copies name an extension we *did* offer, so only the
        // duplicate rule can reject this ServerHello.
        let sh = make_server_hello_body_with_extensions(
            0xC02F,
            &[0x11u8; 32],
            &[
                (ext_type::EXTENDED_MASTER_SECRET, Vec::new()),
                (ext_type::EXTENDED_MASTER_SECRET, Vec::new()),
            ],
        );
        let error = feed_server_hello(&mut hs, &sh).expect_err("a repeated extension must abort");

        assert!(
            error
                .to_string()
                .contains("duplicate ServerHello extension 0x0017"),
            "expected a duplicate-extension rejection, got: {error}"
        );
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::IllegalParameter),
        );
    }

    #[test]
    fn full_handshake_completes_after_a_real_client_hello() {
        let profile = crate::profile::presets::chrome_150();
        let mut hs = handshake_after_real_client_hello(&profile);

        let sh = make_server_hello_body_with_extensions(
            0xC02F,
            &[0x11u8; 32],
            &[
                (ext_type::EXTENDED_MASTER_SECRET, Vec::new()),
                (ext_type::ALPN, alpn_extension_body("h2")),
            ],
        );
        feed_server_hello(&mut hs, &sh).expect("ServerHello");

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .expect("Certificate");

        let ske_body = make_ske_body(&generate_p256_public_key());
        hs.process_handshake_record(&build_handshake_message(0x0C, &ske_body))
            .expect("ServerKeyExchange");

        let action = hs
            .process_handshake_record(&build_handshake_message(0x0E, &[]))
            .expect("ServerHelloDone");

        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert!(!flight.client_key_exchange.is_empty());
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
        assert!(hs.master_secret().is_some());
    }

    /// RFC 5746 §3.4/§3.6: `renegotiation_info` in a ServerHello answers either
    /// the extension or the `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` cipher suite,
    /// so the SCSV alone has to count as having offered it.
    #[test]
    fn renegotiation_info_is_solicited_by_the_scsv_alone() {
        let mut profile = crate::profile::presets::chrome_150();
        profile
            .extensions
            .retain(|spec| spec.extension_type != ext_type::RENEGOTIATION_INFO);
        assert!(
            !profile
                .cipher_suites
                .contains(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
            "the fixture depends on the preset not already sending the SCSV"
        );

        let reneg_sh = |random: &[u8; 32]| {
            make_server_hello_body_with_extensions(
                0xC02F,
                random,
                &[(ext_type::RENEGOTIATION_INFO, vec![0x00])],
            )
        };

        // Neither signal: the answer is unsolicited.
        let mut without_scsv = handshake_after_real_client_hello(&profile);
        let error = feed_server_hello(&mut without_scsv, &reneg_sh(&[0x11u8; 32]))
            .expect_err("with neither signal sent, renegotiation_info is unsolicited");
        assert!(
            error.to_string().contains("0xff01"),
            "expected a renegotiation_info rejection, got: {error}"
        );

        // SCSV instead of the extension: the same answer is solicited.
        let mut scsv_profile = profile.clone();
        scsv_profile
            .cipher_suites
            .push(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        let mut with_scsv = handshake_after_real_client_hello(&scsv_profile);
        feed_server_hello(&mut with_scsv, &reneg_sh(&[0x11u8; 32]))
            .expect("the SCSV solicits renegotiation_info just as the extension does");
        assert_eq!(with_scsv.state(), Tls12State::WaitCertificate);
    }

    #[test]
    fn real_client_hello_records_the_extension_types_it_sent() {
        let profile = crate::profile::presets::chrome_150();
        let hs = handshake_after_real_client_hello(&profile);

        let offered = hs
            .offered_extensions
            .clone()
            .expect("extension types recorded");
        for expected in [
            ext_type::ALPN,
            ext_type::EXTENDED_MASTER_SECRET,
            ext_type::RENEGOTIATION_INFO,
        ] {
            assert!(
                offered.contains(&expected),
                "chrome_150 sends 0x{expected:04x}, so it must appear in the recorded offer"
            );
        }
        assert!(
            !offered.contains(&ext_type::RECORD_SIZE_LIMIT),
            "record_size_limit was not offered, so it must not appear in the recorded offer"
        );
    }

    fn generate_p256_public_key() -> Vec<u8> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let priv_key = aws_lc_rs::agreement::EphemeralPrivateKey::generate(
            &aws_lc_rs::agreement::ECDH_P256,
            &rng,
        )
        .unwrap();
        priv_key.compute_public_key().unwrap().as_ref().to_vec()
    }

    fn new_test_handshake() -> Tls12Handshake {
        Tls12Handshake::new(
            [0x42u8; 32],
            "test.example.com",
            VerificationPolicy::Insecure,
        )
    }

    // ========================================================================
    // Getter/setter initial values
    // ========================================================================

    #[test]
    fn initial_getters_are_none() {
        let hs = new_test_handshake();
        assert!(hs.negotiated_alpn().is_none());
        assert!(hs.master_secret().is_none());
        assert!(hs.negotiated_cipher_suite().is_none());
        assert!(!hs.is_abbreviated());
    }

    #[test]
    fn set_session_ticket_master_secret_enables_resumption() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xAA; 48]);
        assert!(hs.resumed_master_secret.is_some());
    }

    #[test]
    fn set_custom_ca_anchors() {
        let mut hs = new_test_handshake();
        assert!(hs.custom_ca_anchors.is_none());
        hs.set_custom_ca_anchors(Arc::new(vec![]));
        assert!(hs.custom_ca_anchors.is_some());
    }

    // ========================================================================
    // feed_client_hello / feed_handshake_message
    // ========================================================================

    #[test]
    fn feed_client_hello_initializes_transcript() {
        let mut hs = new_test_handshake();
        assert!(hs.transcript.is_none());
        hs.feed_client_hello(b"fake-client-hello");
        assert!(hs.transcript.is_some());
        assert_eq!(hs.client_hello_bytes, b"fake-client-hello");
    }

    #[test]
    fn feed_handshake_message_updates_transcript() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let hash_before = hs.transcript.as_ref().unwrap().current_hash();
        hs.feed_handshake_message(b"extra-data");
        let hash_after = hs.transcript.as_ref().unwrap().current_hash();
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn notify_server_ccs_in_correct_state() {
        let mut hs = new_test_handshake();
        hs.state = Tls12State::WaitServerChangeCipherSpec;
        hs.notify_server_ccs_received();
        assert_eq!(hs.state(), Tls12State::WaitServerFinished);
    }

    #[test]
    fn notify_server_ccs_in_wrong_state_is_noop() {
        let mut hs = new_test_handshake();
        assert_eq!(hs.state(), Tls12State::WaitServerHello);
        hs.notify_server_ccs_received();
        assert_eq!(hs.state(), Tls12State::WaitServerHello);
    }

    // ========================================================================
    // process_handshake_record — error cases
    // ========================================================================

    #[test]
    fn record_too_short_for_header() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let result = hs.process_handshake_record(&[0x02, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn record_truncated_body() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        // Claim length of 100 but only provide 2 bytes of body
        let result = hs.process_handshake_record(&[0x02, 0x00, 0x00, 0x64, 0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_message_type_in_wait_server_hello() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        // Send a Certificate (0x0B) when expecting ServerHello (0x02)
        let record = build_handshake_message(0x0B, &[0x00; 38]);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    // ========================================================================
    // process_server_hello
    // ========================================================================

    #[test]
    fn server_hello_too_short() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &[0x03, 0x03]);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn server_hello_unknown_cipher_suite() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body(0xFFFF, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn server_hello_valid_transitions_to_wait_certificate() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body(0xC02F, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        let action = hs.process_handshake_record(&record).unwrap();
        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitCertificate);
        assert_eq!(
            hs.negotiated_cipher_suite(),
            Some(Tls12CipherSuite::EcdheRsaAes128GcmSha256)
        );
    }

    #[test]
    fn server_hello_with_alpn() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body_with_alpn(0xC02F, &[0u8; 32], "h2");
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.negotiated_alpn(), Some("h2"));
    }

    #[test]
    fn server_hello_with_extended_master_secret() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body_with_ems(0xC02F, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert!(hs.use_extended_master_secret);
    }

    /// RFC 8449 §4 puts `record_size_limit` in EncryptedExtensions only for TLS
    /// 1.3; under TLS 1.2 it rides in the ServerHello, and it bounds the
    /// records we send.
    #[test]
    fn server_hello_with_record_size_limit() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body_with_record_size_limit(0xC02F, &[0u8; 32], 512);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(
            hs.peer_record_size_limit(),
            Some(512),
            "the ServerHello record_size_limit must be captured"
        );
    }

    #[test]
    fn server_hello_without_record_size_limit_leaves_it_unset() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body_with_ems(0xC02F, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.peer_record_size_limit(), None);
    }

    /// RFC 8449 §4: a value below 64 is a fatal `illegal_parameter`.
    #[test]
    fn server_hello_record_size_limit_below_64_is_illegal_parameter() {
        for raw in [0u16, 1, 63] {
            let mut hs = new_test_handshake();
            hs.feed_client_hello(b"ch");
            let body = make_server_hello_body_with_record_size_limit(0xC02F, &[0u8; 32], raw);
            let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
            let error = hs
                .process_handshake_record(&record)
                .expect_err("a record_size_limit below 64 must abort the handshake");
            let description = error.as_alert().map(|alert| alert.description);
            assert_eq!(
                description,
                Some(AlertDescription::IllegalParameter),
                "value {raw} must abort with illegal_parameter, got {description:?}"
            );
            assert_eq!(hs.peer_record_size_limit(), None);
        }
    }

    #[test]
    fn server_hello_sha384_suite_restarts_transcript() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        // 0xC030 = ECDHE_RSA_WITH_AES_256_GCM_SHA384 → SHA384
        let body = make_server_hello_body(0xC030, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.prf_algorithm, PrfAlgorithm::Sha384);
        let hash = hs.transcript.as_ref().unwrap().current_hash();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn server_hello_with_resumption_waits_certificate_or_abbreviated() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xBB; 48]);
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body(0xC02F, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.state(), Tls12State::WaitCertificateOrAbbreviated);
    }

    // ========================================================================
    // process_certificate
    // ========================================================================

    #[test]
    fn certificate_empty_chain() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        // First process a valid ServerHello
        let sh = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(handshake_type::SERVER_HELLO, &sh))
            .unwrap();
        // Now send an empty Certificate
        let cert_body = [0x00, 0x00, 0x00]; // total_len = 0
        let record = build_handshake_message(handshake_type::CERTIFICATE, &cert_body);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_valid_transitions_to_wait_ske() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let sh = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(handshake_type::SERVER_HELLO, &sh))
            .unwrap();
        let cert_body = make_certificate_body(&[&[0xDE, 0xAD, 0xBE, 0xEF]]);
        let record = build_handshake_message(handshake_type::CERTIFICATE, &cert_body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.state(), Tls12State::WaitServerKeyExchange);
        assert_eq!(hs.server_certificates.len(), 1);
    }

    #[test]
    fn certificate_body_too_short() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let sh = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(handshake_type::SERVER_HELLO, &sh))
            .unwrap();
        let record = build_handshake_message(handshake_type::CERTIFICATE, &[0x00, 0x00]);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    // ========================================================================
    // process_server_key_exchange
    // ========================================================================

    fn setup_to_wait_ske(hs: &mut Tls12Handshake) {
        hs.feed_client_hello(b"ch");
        let sh = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(handshake_type::SERVER_HELLO, &sh))
            .unwrap();
        let cert_body = make_certificate_body(&[&[0xDE, 0xAD, 0xBE, 0xEF]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();
    }

    #[test]
    fn ske_too_short() {
        let mut hs = new_test_handshake();
        setup_to_wait_ske(&mut hs);
        let record = build_handshake_message(0x0C, &[0x03, 0x00]);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn ske_unsupported_curve_type() {
        let mut hs = new_test_handshake();
        setup_to_wait_ske(&mut hs);
        // curve_type = 0x01 (explicit_prime, not supported)
        let mut body = vec![0x01, 0x00, 0x17, 65];
        body.extend_from_slice(&[0u8; 65]); // dummy pubkey
        body.extend_from_slice(&[0x04, 0x03, 0x00, 0x08]);
        body.extend_from_slice(&[0u8; 8]); // dummy sig
        let record = build_handshake_message(0x0C, &body);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn ske_valid_transitions_to_wait_shd() {
        let mut hs = new_test_handshake();
        setup_to_wait_ske(&mut hs);
        let server_pub = generate_p256_public_key();
        let ske_body = make_ske_body(&server_pub);
        let record = build_handshake_message(0x0C, &ske_body);
        hs.process_handshake_record(&record).unwrap();
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);
        assert!(hs.server_kx_params.is_some());
    }

    #[test]
    fn ske_signature_truncated() {
        let mut hs = new_test_handshake();
        setup_to_wait_ske(&mut hs);
        let server_pub = generate_p256_public_key();
        let mut body = Vec::new();
        body.push(0x03);
        body.extend_from_slice(&[0x00, 0x17]);
        body.push(server_pub.len() as u8);
        body.extend_from_slice(&server_pub);
        // sig_algo + sig_len that claims more data than available
        body.extend_from_slice(&[0x04, 0x03, 0x01, 0x00]); // sig_len = 256
        let record = build_handshake_message(0x0C, &body);
        let result = hs.process_handshake_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_status_in_ske_state_continues() {
        let mut hs = new_test_handshake();
        setup_to_wait_ske(&mut hs);
        // CertificateStatus (0x16) should be accepted and state remains WaitServerKeyExchange
        let record =
            build_handshake_message(handshake_type::CERTIFICATE_STATUS, &[0x01, 0x00, 0x00]);
        let action = hs.process_handshake_record(&record).unwrap();
        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitServerKeyExchange);
    }

    // ========================================================================
    // Full handshake flow → SendClientFlight
    // ========================================================================

    fn setup_to_wait_shd(hs: &mut Tls12Handshake) -> Vec<u8> {
        setup_to_wait_ske(hs);
        let server_pub = generate_p256_public_key();
        let ske_body = make_ske_body(&server_pub);
        hs.process_handshake_record(&build_handshake_message(0x0C, &ske_body))
            .unwrap();
        server_pub
    }

    #[test]
    fn server_hello_done_produces_client_flight() {
        let mut hs = new_test_handshake();
        setup_to_wait_shd(&mut hs);
        let shd_record = build_handshake_message(0x0E, &[]);
        let action = hs.process_handshake_record(&shd_record).unwrap();
        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert!(flight.client_certificate.is_none());
                assert!(!flight.client_key_exchange.is_empty());
                assert!(!flight.client_finished.is_empty());
                assert_eq!(
                    flight.traffic_keys.cipher_suite,
                    Tls12CipherSuite::EcdheRsaAes128GcmSha256
                );
                assert_eq!(flight.traffic_keys.client_write_key.len(), 16);
                assert_eq!(flight.traffic_keys.server_write_key.len(), 16);
                assert_eq!(flight.traffic_keys.client_write_iv.len(), 4);
                assert_eq!(flight.traffic_keys.server_write_iv.len(), 4);
                // GCM suite → no MAC keys
                assert!(flight.traffic_keys.client_write_mac_key.is_empty());
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
        assert!(hs.master_secret().is_some());
        assert_eq!(hs.master_secret().unwrap().len(), 48);
        assert_eq!(hs.state(), Tls12State::WaitServerChangeCipherSpec);
    }

    #[test]
    fn certificate_request_produces_empty_client_certificate() {
        let mut hs = new_test_handshake();
        setup_to_wait_shd(&mut hs);
        let cr_record = build_handshake_message(0x0D, &[0x01, 0x01, 0x00, 0x00, 0x00]);
        let action = hs.process_handshake_record(&cr_record).unwrap();
        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);

        let action = hs
            .process_handshake_record(&build_handshake_message(0x0E, &[]))
            .unwrap();
        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert_eq!(
                    flight.client_certificate.as_deref(),
                    Some(&[handshake_type::CERTIFICATE, 0, 0, 3, 0, 0, 0][..])
                );
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
    }

    // ========================================================================
    // Full handshake → server Finished verification
    // ========================================================================

    #[test]
    fn full_handshake_server_finished() {
        let client_random = [0x42u8; 32];
        let server_random = [0x11u8; 32];
        let mut hs = Tls12Handshake::new(
            client_random,
            "test.example.com",
            VerificationPolicy::Insecure,
        );

        let ch_bytes = b"fake-client-hello";
        hs.feed_client_hello(ch_bytes);

        let sh_body = make_server_hello_body(0xC02F, &server_random);
        let sh_record = build_handshake_message(handshake_type::SERVER_HELLO, &sh_body);
        hs.process_handshake_record(&sh_record).unwrap();

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        let cert_record = build_handshake_message(handshake_type::CERTIFICATE, &cert_body);
        hs.process_handshake_record(&cert_record).unwrap();

        let server_pub = generate_p256_public_key();
        let ske_body = make_ske_body(&server_pub);
        let ske_record = build_handshake_message(0x0C, &ske_body);
        hs.process_handshake_record(&ske_record).unwrap();

        let shd_record = build_handshake_message(0x0E, &[]);
        let action = hs.process_handshake_record(&shd_record).unwrap();
        let flight = match action {
            Tls12HandshakeAction::SendClientFlight(f) => f,
            other => panic!("expected SendClientFlight, got {other:?}"),
        };

        // Compute the transcript hash independently
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(ch_bytes);
        ctx.update(&sh_record);
        ctx.update(&cert_record);
        ctx.update(&ske_record);
        ctx.update(&shd_record);
        ctx.update(&flight.client_key_exchange);
        ctx.update(&flight.client_finished);
        let transcript_hash = ctx.finish();

        let master_secret = hs.master_secret().unwrap();
        let expected_verify_data = prf::compute_verify_data(
            PrfAlgorithm::Sha256,
            master_secret,
            "server finished",
            transcript_hash.as_ref(),
        )
        .unwrap();

        hs.notify_server_ccs_received();
        assert_eq!(hs.state(), Tls12State::WaitServerFinished);

        let action = hs.process_server_finished(&expected_verify_data).unwrap();
        assert!(matches!(action, Tls12HandshakeAction::Complete(_)));
        assert_eq!(hs.state(), Tls12State::Connected);
    }

    #[test]
    fn server_finished_wrong_state() {
        let mut hs = new_test_handshake();
        let result = hs.process_server_finished(&[0u8; 12]);
        assert!(result.is_err());
    }

    #[test]
    fn server_finished_bad_length() {
        let mut hs = new_test_handshake();
        hs.state = Tls12State::WaitServerFinished;
        hs.master_secret = Some(vec![0u8; 48]);
        hs.transcript = Some(TranscriptHash::new(PrfAlgorithm::Sha256));
        hs.cipher_suite = Some(Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        let result = hs.process_server_finished(&[0u8; 7]); // bad length
        assert!(result.is_err());
    }

    #[test]
    fn server_finished_verify_data_mismatch() {
        let mut hs = new_test_handshake();
        hs.state = Tls12State::WaitServerFinished;
        hs.master_secret = Some(vec![0u8; 48]);
        hs.transcript = Some(TranscriptHash::new(PrfAlgorithm::Sha256));
        hs.cipher_suite = Some(Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        let result = hs.process_server_finished(&[0xFFu8; 12]); // wrong verify_data
        assert!(result.is_err());
    }

    // ========================================================================
    // Abbreviated handshake
    // ========================================================================

    #[test]
    fn abbreviated_accept_ccs_wrong_state() {
        let mut hs = new_test_handshake();
        let result = hs.accept_abbreviated_ccs();
        assert!(result.is_err());
    }

    #[test]
    fn abbreviated_accept_ccs_no_master_secret() {
        let mut hs = new_test_handshake();
        hs.state = Tls12State::WaitCertificateOrAbbreviated;
        hs.cipher_suite = Some(Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        let result = hs.accept_abbreviated_ccs();
        assert!(result.is_err());
    }

    #[test]
    fn abbreviated_handshake_flow() {
        let client_random = [0x42u8; 32];
        let server_random = [0x11u8; 32];
        let master_secret = vec![0xAA; 48];

        let mut hs = Tls12Handshake::new(
            client_random,
            "test.example.com",
            VerificationPolicy::Insecure,
        );
        hs.set_session_ticket_master_secret(master_secret.clone());

        let ch_bytes = b"fake-client-hello";
        hs.feed_client_hello(ch_bytes);

        let sh_body = make_server_hello_body(0xC02F, &server_random);
        let sh_record = build_handshake_message(handshake_type::SERVER_HELLO, &sh_body);
        hs.process_handshake_record(&sh_record).unwrap();
        assert_eq!(hs.state(), Tls12State::WaitCertificateOrAbbreviated);

        let keys = hs.accept_abbreviated_ccs().unwrap();
        assert!(hs.is_abbreviated());
        assert_eq!(hs.state(), Tls12State::WaitServerFinished);
        assert_eq!(keys.cipher_suite, Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        assert_eq!(keys.client_write_key.len(), 16);
        assert_eq!(keys.server_write_key.len(), 16);
    }

    #[test]
    fn abbreviated_server_finished_wrong_state() {
        let mut hs = new_test_handshake();
        let result = hs.process_abbreviated_server_finished(&[0u8; 12]);
        assert!(result.is_err());
    }

    #[test]
    fn abbreviated_full_flow_with_server_finished() {
        let client_random = [0x42u8; 32];
        let server_random = [0x11u8; 32];
        let master_secret = vec![0xAA; 48];

        let mut hs = Tls12Handshake::new(
            client_random,
            "test.example.com",
            VerificationPolicy::Insecure,
        );
        hs.set_session_ticket_master_secret(master_secret.clone());

        let ch_bytes = b"fake-client-hello";
        hs.feed_client_hello(ch_bytes);

        let sh_body = make_server_hello_body(0xC02F, &server_random);
        let sh_record = build_handshake_message(handshake_type::SERVER_HELLO, &sh_body);
        hs.process_handshake_record(&sh_record).unwrap();

        hs.accept_abbreviated_ccs().unwrap();

        // Compute expected server Finished verify_data
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(ch_bytes);
        ctx.update(&sh_record);
        let transcript_hash = ctx.finish();

        let expected_verify_data = prf::compute_verify_data(
            PrfAlgorithm::Sha256,
            &master_secret,
            "server finished",
            transcript_hash.as_ref(),
        )
        .unwrap();

        let result = hs.process_abbreviated_server_finished(&expected_verify_data);
        assert!(result.is_ok());
        let flight = result.unwrap();
        assert!(!flight.client_finished.is_empty());
        assert_eq!(hs.state(), Tls12State::Connected);
    }

    // ========================================================================
    // Abbreviated fallback to full handshake
    // ========================================================================

    #[test]
    fn abbreviated_rejected_falls_back_to_full() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xBB; 48]);
        hs.feed_client_hello(b"ch");

        let sh_body = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();
        assert_eq!(hs.state(), Tls12State::WaitCertificateOrAbbreviated);

        // Server sends Certificate instead of CCS → rejection, fall back to full
        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();
        assert_eq!(hs.state(), Tls12State::WaitServerKeyExchange);
        assert!(hs.resumed_master_secret.is_none());
    }

    #[test]
    fn abbreviated_new_session_ticket() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xBB; 48]);
        hs.feed_client_hello(b"ch");

        let sh_body = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();

        // NewSessionTicket (type 0x04)
        let nst_body = vec![0x00, 0x00, 0x0E, 0x10, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        let record = build_handshake_message(0x04, &nst_body);
        let action = hs.process_handshake_record(&record).unwrap();
        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitCertificateOrAbbreviated);
    }

    // ========================================================================
    // Extended master secret in full handshake
    // ========================================================================

    #[test]
    fn full_handshake_with_extended_master_secret() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");

        let sh_body = make_server_hello_body_with_ems(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();
        assert!(hs.use_extended_master_secret);

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();

        let server_pub = generate_p256_public_key();
        let ske_body = make_ske_body(&server_pub);
        hs.process_handshake_record(&build_handshake_message(0x0C, &ske_body))
            .unwrap();

        let shd_record = build_handshake_message(0x0E, &[]);
        let action = hs.process_handshake_record(&shd_record).unwrap();
        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert!(!flight.client_key_exchange.is_empty());
                assert_eq!(flight.traffic_keys.client_write_key.len(), 16);
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
        assert!(hs.master_secret().is_some());
    }

    // ========================================================================
    // RSA key exchange
    // ========================================================================

    fn generate_rsa_cert_der() -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("RSA key gen");
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        cert.der().to_vec()
    }

    #[test]
    fn rsa_suite_certificate_transitions_to_wait_shd() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");

        // 0x0035 = TLS_RSA_WITH_AES_256_CBC_SHA
        let sh_body = make_server_hello_body(0x0035, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();
        assert_eq!(
            hs.negotiated_cipher_suite(),
            Some(Tls12CipherSuite::RsaAes256CbcSha)
        );

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD, 0xBE, 0xEF]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();

        // RSA suites skip ServerKeyExchange, go directly to WaitServerHelloDone
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);
    }

    #[test]
    fn rsa_suite_server_hello_done_produces_client_flight() {
        let cert_der = generate_rsa_cert_der();

        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");

        // 0x0035 = TLS_RSA_WITH_AES_256_CBC_SHA
        let sh_body = make_server_hello_body(0x0035, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();

        let cert_body = make_certificate_body(&[&cert_der]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);

        let shd_record = build_handshake_message(0x0E, &[]);
        let action = hs.process_handshake_record(&shd_record).unwrap();
        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert!(!flight.client_key_exchange.is_empty());
                assert!(!flight.client_finished.is_empty());
                assert_eq!(
                    flight.traffic_keys.cipher_suite,
                    Tls12CipherSuite::RsaAes256CbcSha
                );
                // AES-256 key = 32 bytes
                assert_eq!(flight.traffic_keys.client_write_key.len(), 32);
                assert_eq!(flight.traffic_keys.server_write_key.len(), 32);
                // CBC IV = 16 bytes
                assert_eq!(flight.traffic_keys.client_write_iv.len(), 16);
                assert_eq!(flight.traffic_keys.server_write_iv.len(), 16);
                // HMAC-SHA1 MAC key = 20 bytes
                assert_eq!(flight.traffic_keys.client_write_mac_key.len(), 20);
                assert_eq!(flight.traffic_keys.server_write_mac_key.len(), 20);

                // Verify CKE message format: type(1) + len(3) + enc_pms_len(2) + encrypted_pms
                assert_eq!(flight.client_key_exchange[0], 0x10); // ClientKeyExchange type
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
        assert!(hs.master_secret().is_some());
        assert_eq!(hs.master_secret().unwrap().len(), 48);
        assert_eq!(hs.state(), Tls12State::WaitServerChangeCipherSpec);
    }

    #[test]
    fn rsa_gcm_suite_produces_correct_key_sizes() {
        let cert_der = generate_rsa_cert_der();

        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");

        // 0x009C = TLS_RSA_WITH_AES_128_GCM_SHA256
        let sh_body = make_server_hello_body(0x009C, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .unwrap();

        let cert_body = make_certificate_body(&[&cert_der]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .unwrap();
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);

        let shd_record = build_handshake_message(0x0E, &[]);
        let action = hs.process_handshake_record(&shd_record).unwrap();
        match action {
            Tls12HandshakeAction::SendClientFlight(flight) => {
                assert_eq!(
                    flight.traffic_keys.cipher_suite,
                    Tls12CipherSuite::RsaAes128GcmSha256
                );
                // AES-128 key = 16 bytes
                assert_eq!(flight.traffic_keys.client_write_key.len(), 16);
                // GCM IV = 4 bytes
                assert_eq!(flight.traffic_keys.client_write_iv.len(), 4);
                // AEAD → no MAC keys
                assert!(flight.traffic_keys.client_write_mac_key.is_empty());
            }
            other => panic!("expected SendClientFlight, got {other:?}"),
        }
    }

    #[test]
    fn rsa_key_exchange_without_certificate_fails() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        hs.cipher_suite = Some(Tls12CipherSuite::RsaAes256CbcSha);
        hs.state = Tls12State::WaitServerHelloDone;
        hs.transcript = Some(TranscriptHash::new(PrfAlgorithm::Sha256));

        let shd_record = build_handshake_message(0x0E, &[]);
        let result = hs.process_handshake_record(&shd_record);
        assert!(result.is_err());
    }

    #[test]
    fn all_rsa_suites_resolve_from_code_point() {
        let rsa_suites = [
            (0x0035, Tls12CipherSuite::RsaAes256CbcSha),
            (0x002F, Tls12CipherSuite::RsaAes128CbcSha),
            (0x003D, Tls12CipherSuite::RsaAes256CbcSha256),
            (0x003C, Tls12CipherSuite::RsaAes128CbcSha256),
            (0x009C, Tls12CipherSuite::RsaAes128GcmSha256),
            (0x009D, Tls12CipherSuite::RsaAes256GcmSha384),
        ];
        for (code, expected) in &rsa_suites {
            let suite = Tls12CipherSuite::from_code_point(*code);
            assert_eq!(suite, Some(*expected), "code 0x{code:04x}");
            assert_eq!(
                suite.unwrap().key_exchange(),
                crate::crypto::tls12_cipher::Tls12KeyExchange::Rsa,
                "code 0x{code:04x} should use RSA key exchange"
            );
            assert_eq!(suite.unwrap().code_point(), *code);
        }
    }

    // ========================================================================
    // Extended master secret on resumption (RFC 7627 §5.3)
    // ========================================================================

    /// Run an abbreviated handshake up to the server's CCS, choosing the
    /// original session's EMS state and the resuming ServerHello's EMS
    /// extension independently, and report what `accept_abbreviated_ccs` made
    /// of the pair.
    fn resume_with_ems(
        original_used_ems: Option<bool>,
        server_hello_has_ems: bool,
    ) -> Result<Tls12TrafficKeys> {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_resumption(vec![0xAA; 48], original_used_ems);
        hs.feed_client_hello(b"fake-client-hello");

        let server_random = [0x11u8; 32];
        let sh_body = if server_hello_has_ems {
            make_server_hello_body_with_ems(0xC02F, &server_random)
        } else {
            make_server_hello_body(0xC02F, &server_random)
        };
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .expect("ServerHello parses");
        assert_eq!(hs.state(), Tls12State::WaitCertificateOrAbbreviated);
        assert_eq!(hs.used_extended_master_secret(), server_hello_has_ems);

        // Server goes straight to CCS: it accepted the abbreviated handshake.
        hs.accept_abbreviated_ccs()
    }

    /// RFC 7627 §5.3: "If the original session did not use the
    /// `extended_master_secret` extension but the new ServerHello contains the
    /// extension, the client MUST abort the handshake."
    #[test]
    fn abbreviated_handshake_aborts_when_server_adds_ems_to_a_legacy_session() {
        let error = resume_with_ems(Some(false), true)
            .expect_err("a non-EMS session resumed with EMS asserted must abort");
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::HandshakeFailure),
            "expected a fatal handshake_failure, got {error:?}"
        );
    }

    /// RFC 7627 §5.3: "If the original session used the extension but the new
    /// ServerHello does not contain the extension, the client MUST abort the
    /// handshake." §5.4 keeps this a MUST even though continuing would still
    /// be protected by the original session's extended master secret.
    #[test]
    fn abbreviated_handshake_aborts_when_server_drops_ems_from_an_ems_session() {
        let error = resume_with_ems(Some(true), false)
            .expect_err("an EMS session resumed without EMS must abort");
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::HandshakeFailure),
            "expected a fatal handshake_failure, got {error:?}"
        );
    }

    /// Consistent state in either direction resumes normally — the check is a
    /// mismatch detector, not a requirement that every session use EMS.
    #[test]
    fn abbreviated_handshake_continues_when_ems_state_matches() {
        for used_ems in [true, false] {
            let keys =
                resume_with_ems(Some(used_ems), used_ems).expect("matching EMS state must resume");
            assert_eq!(
                keys.cipher_suite,
                Tls12CipherSuite::EcdheRsaAes128GcmSha256,
                "original_used_ems={used_ems}"
            );
            assert_eq!(keys.client_write_key.len(), 16);
        }
    }

    /// A ticket stored without any record of the original session's EMS state
    /// cannot be checked, and must not be guessed at in either direction:
    /// both ServerHello shapes still resume.
    #[test]
    fn abbreviated_handshake_without_recorded_ems_state_skips_the_check() {
        for server_hello_has_ems in [true, false] {
            let keys = resume_with_ems(None, server_hello_has_ems)
                .expect("an unrecorded EMS state leaves resumption as it was");
            assert_eq!(keys.cipher_suite, Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        }
    }

    /// The legacy setter is the "state not recorded" path.
    #[test]
    fn set_session_ticket_master_secret_leaves_ems_state_unknown() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xBB; 48]);
        assert!(hs.resumed_master_secret.is_some());
        assert_eq!(hs.resumed_session_used_ems, None);
    }

    /// The flag a ticket store needs to persist (RFC 7627 §5.4) is whatever the
    /// ServerHello of the *original* handshake agreed to.
    #[test]
    fn used_extended_master_secret_reports_serverhello_agreement() {
        for server_hello_has_ems in [true, false] {
            let mut hs = new_test_handshake();
            hs.feed_client_hello(b"ch");
            let body = if server_hello_has_ems {
                make_server_hello_body_with_ems(0xC02F, &[0u8; 32])
            } else {
                make_server_hello_body(0xC02F, &[0u8; 32])
            };
            hs.process_handshake_record(&build_handshake_message(
                handshake_type::SERVER_HELLO,
                &body,
            ))
            .expect("ServerHello parses");
            assert_eq!(hs.used_extended_master_secret(), server_hello_has_ems);
        }
    }

    /// A rejected ticket drops the old session's EMS state along with its
    /// master secret — the full handshake that follows negotiates its own.
    #[test]
    fn abbreviated_rejection_clears_recorded_ems_state() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_resumption(vec![0xBB; 48], Some(true));
        hs.feed_client_hello(b"ch");

        let sh_body = make_server_hello_body(0xC02F, &[0u8; 32]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::SERVER_HELLO,
            &sh_body,
        ))
        .expect("ServerHello parses");
        assert_eq!(hs.resumed_session_used_ems, Some(true));

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .expect("Certificate parses");
        assert!(hs.resumed_master_secret.is_none());
        assert_eq!(hs.resumed_session_used_ems, None);
    }
}
