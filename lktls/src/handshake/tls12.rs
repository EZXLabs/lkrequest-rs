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

use crate::crypto::kx::{self, KxGroup};
use crate::crypto::prf::{self, PrfAlgorithm};
use crate::crypto::tls12_cipher::{CbcMacMode, Tls12CipherSuite, Tls12KeyExchange};
use crate::error::{AlertDescription, Result, TlsError};
use crate::extensions::tls12::ServerExtensions;
use crate::handshake::handshake_type;
use crate::handshake::tls13::{client_hello_extensions, client_hello_legacy_offer};
use crate::profile::types::ext_type;
use crate::verify::policy::VerificationPolicy;

mod client;
mod state;
use state::Phase;

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
        self.to_record_cipher_with_mode(client_side, CbcMacMode::MacThenEncrypt)
    }

    /// Create record protection using this connection's negotiated CBC mode.
    /// The original constructor retains MAC-then-encrypt for compatibility.
    pub fn to_record_cipher_with_mode(
        &self,
        client_side: bool,
        mode: CbcMacMode,
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
        self.cipher_suite
            .descriptor()
            .record_cipher_with_mode(key, iv, mac_key, mode)
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
    suite.descriptor().record_cipher(key, iv, mac_key)
}

// ---------------------------------------------------------------------------
// TLS 1.2 Handshake state machine
// ---------------------------------------------------------------------------

/// TLS 1.2 handshake processor.
///
/// Processes incoming handshake records and produces actions for the caller.
pub struct Tls12Handshake {
    state: Phase,
    client_random: [u8; 32],
    hostname: String,
    verification_policy: VerificationPolicy,
    custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,
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
    /// Protocol identifiers from the actual ClientHello, including raw overrides.
    offered_alpn_protocols: Option<Vec<Vec<u8>>>,
    offered_cipher_suites: Option<Vec<u16>>,
    offered_compression_methods: Option<Vec<u8>>,
}

/// The signature algorithms a server may assume when the ClientHello carried no
/// `signature_algorithms` extension (RFC 5246 §7.4.1.4.1): SHA-1 with each
/// certificate type the negotiated cipher suite can use.
const TLS12_DEFAULT_SIGNATURE_ALGORITHMS: [u16; 3] = [
    0x0201, // rsa_pkcs1_sha1
    0x0202, // dsa_sha1
    0x0203, // ecdsa_sha1
];

impl Tls12Handshake {
    fn record_offer(&mut self, ch_bytes: &[u8]) {
        let Some(extensions) = client_hello_extensions(ch_bytes) else {
            // Not a parseable ClientHello (unit tests feed placeholder bytes);
            // there is nothing to compare a server's choice against.
            self.offered_groups = None;
            self.offered_signature_algorithms = None;
            self.offered_extensions = None;
            self.offered_alpn_protocols = None;
            self.offered_cipher_suites = None;
            self.offered_compression_methods = None;
            return;
        };
        let body = |target: u16| {
            extensions
                .iter()
                .find(|(extension_type, _)| *extension_type == target)
                .map(|(_, body)| *body)
        };
        if let Some((suites, compression)) = client_hello_legacy_offer(ch_bytes) {
            self.offered_cipher_suites = Some(suites);
            self.offered_compression_methods = Some(compression);
        } else {
            self.offered_cipher_suites = None;
            self.offered_compression_methods = None;
        }
        self.offered_alpn_protocols = Some(
            body(ext_type::ALPN)
                .and_then(crate::extensions::alpn::parse_alpn_list_bytes)
                .map(|protocols| protocols.into_iter().map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
        );

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
    client_hello_legacy_offer(ch_bytes)
        .is_some_and(|(suites, _)| suites.contains(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
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

    fn pending_resumption(hs: &Tls12Handshake) -> Option<&state::Resumption> {
        match &hs.state {
            Phase::Initial(initial) => initial.resumption.as_ref(),
            Phase::ServerFlight(state::ServerFlight {
                step: state::ServerFlightStep::CertificateOrResume(resumption),
                ..
            }) => Some(resumption),
            _ => None,
        }
    }

    fn transcript_hash(hs: &Tls12Handshake) -> Vec<u8> {
        match &hs.state {
            Phase::ServerFlight(flight) => flight.transcript.current_hash(),
            Phase::Finishing(finish) => finish.transcript.current_hash(),
            _ => panic!("fixture needs an active negotiated transcript"),
        }
    }

    fn full_handshake_waiting_for_ccs() -> Tls12Handshake {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        setup_to_wait_shd(&mut hs);
        assert!(matches!(
            hs.process_handshake_record(&build_handshake_message(14, &[]))
                .unwrap(),
            Tls12HandshakeAction::SendClientFlight(_)
        ));
        hs
    }

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
        body.extend_from_slice(&[0x04, 0x01]); // RSA/SHA-256 for the ECDHE_RSA fixture
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

        let sh_body = make_server_hello_body(0xC02B, &[0x11u8; 32]);
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
        let offered = 0x0403;
        assert!(profile.signature_algorithms.contains(&offered));
        let mut hs = handshake_awaiting_ske(&profile);

        let ske = make_ske_body_with(0x0017, offered, &generate_p256_public_key());
        let action = hs
            .process_handshake_record(&build_handshake_message(0x0C, &ske))
            .expect("an offered signature algorithm must be accepted");

        assert!(matches!(action, Tls12HandshakeAction::ContinueReading));
        assert_eq!(hs.state(), Tls12State::WaitServerHelloDone);
    }

    #[test]
    fn ske_rejects_signature_family_from_another_suite_even_when_insecure() {
        let profile = crate::profile::presets::chrome_150();
        let mut hs = handshake_awaiting_ske(&profile);
        let ske = make_ske_body_with(0x0017, 0x0401, &generate_p256_public_key());
        let error = hs
            .process_handshake_record(&build_handshake_message(0x0c, &ske))
            .unwrap_err();
        assert_eq!(
            error.as_alert().unwrap().description,
            AlertDescription::IllegalParameter
        );
        assert_eq!(hs.state(), Tls12State::WaitServerKeyExchange);
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

        assert!(hs.used_extended_master_secret());
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
        assert!(pending_resumption(&hs).is_some());
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
        assert!(matches!(&hs.state, Phase::Initial(initial) if initial.client_hello.is_empty()));
        hs.feed_client_hello(b"fake-client-hello");
        assert!(
            matches!(&hs.state, Phase::Initial(initial) if initial.client_hello == b"fake-client-hello")
        );
    }

    #[test]
    fn feed_handshake_message_updates_transcript() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        hs.process_handshake_record(&build_handshake_message(
            2,
            &make_server_hello_body(0xc02f, &[0x11; 32]),
        ))
        .unwrap();
        let hash_before = transcript_hash(&hs);
        hs.feed_handshake_message(b"extra-data");
        let hash_after = transcript_hash(&hs);
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn notify_server_ccs_in_correct_state() {
        let mut hs = full_handshake_waiting_for_ccs();
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
    fn tls12_rejects_alpn_not_in_the_actual_offer() {
        for resuming in [false, true] {
            let mut profile = crate::profile::presets::chrome_155();
            profile.alpn_protocols = vec!["h2".into()];
            let mut handshake = handshake_after_real_client_hello(&profile);
            if resuming {
                handshake.set_session_ticket_master_secret(vec![0xa5; 48]);
            }
            let body = make_server_hello_body_with_alpn(0xc02f, &[0x55; 32], "h3");
            assert!(
                matches!(handshake.process_handshake_record(&build_handshake_message(2, &body)), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
            );
        }
    }

    #[test]
    fn tls12_rejects_malformed_server_alpn_list() {
        for payload in [
            vec![],
            vec![0, 0],
            vec![0, 2, 0, 0],
            vec![0, 3, 2, b'h', b'2', 0],
            vec![0, 6, 2, b'h', b'2', 2, b'h', b'3'],
        ] {
            let mut handshake =
                handshake_after_real_client_hello(&crate::profile::presets::chrome_155());
            let mut body = make_server_hello_body(0xc02f, &[0x55; 32]);
            body.extend_from_slice(&((4 + payload.len()) as u16).to_be_bytes());
            body.extend_from_slice(&[0, 16]);
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(&payload);
            assert!(
                matches!(handshake.process_handshake_record(&build_handshake_message(2, &body)), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
            );
        }
    }

    #[test]
    fn tls12_alpn_uses_wire_offer_and_accepts_missing_selection() {
        for resuming in [false, true] {
            for selected in [None, Some("h2"), Some("http/1.1")] {
                let profile = crate::profile::presets::chrome_155();
                let mut handshake = handshake_after_real_client_hello(&profile);
                if resuming {
                    handshake.set_session_ticket_master_secret(vec![0xa5; 48]);
                }
                let body = match selected {
                    Some(protocol) => {
                        make_server_hello_body_with_alpn(0xc02f, &[0x55; 32], protocol)
                    }
                    None => make_server_hello_body(0xc02f, &[0x55; 32]),
                };
                feed_server_hello(&mut handshake, &body).unwrap();
                assert_eq!(handshake.negotiated_alpn(), selected);
            }
        }
        let mut profile = crate::profile::presets::chrome_155();
        profile.alpn_protocols = vec!["h2".into()];
        profile
            .extensions
            .iter_mut()
            .find(|extension| extension.extension_type == ext_type::ALPN)
            .unwrap()
            .source = crate::profile::types::ExtensionSource::RawBytes {
            data: "000908687474702f312e31".into(),
        };
        let mut handshake = handshake_after_real_client_hello(&profile);
        let body = make_server_hello_body_with_alpn(0xc02f, &[0x55; 32], "http/1.1");
        feed_server_hello(&mut handshake, &body).unwrap();
        assert_eq!(handshake.negotiated_alpn(), Some("http/1.1"));
    }

    #[test]
    fn tls12_server_hello_extension_framing_is_strict() {
        for extra in [
            vec![0],
            vec![0, 0, 0],
            vec![0, 2, 0, 16],
            vec![0, 4, 0, 16, 0, 5],
        ] {
            let mut handshake =
                handshake_after_real_client_hello(&crate::profile::presets::chrome_155());
            let mut body = make_server_hello_body(0xc02f, &[0x55; 32]);
            body.extend_from_slice(&extra);
            assert!(
                matches!(feed_server_hello(&mut handshake, &body), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
            );
        }
    }

    #[test]
    fn tls12_offer_constraints_apply_to_full_and_resumption_states() {
        for resuming in [false, true] {
            for bad_compression in [false, true] {
                let mut profile = crate::profile::presets::chrome_155();
                if !bad_compression {
                    profile.cipher_suites.retain(|suite| *suite != 0xc02f);
                }
                let mut handshake = handshake_after_real_client_hello(&profile);
                if resuming {
                    handshake.set_session_ticket_master_secret(vec![0xa5; 48]);
                }
                let mut body = make_server_hello_body(0xc02f, &[0x55; 32]);
                if bad_compression {
                    body[37] = 1;
                }
                assert!(
                    matches!(feed_server_hello(&mut handshake, &body), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
                );
            }
        }
    }

    #[test]
    fn valid_legacy_client_without_extensions_still_tracks_cipher_offer() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x42; 32]);
        body.extend_from_slice(&[0, 0, 2, 0xc0, 0x2f, 1, 0]);
        let mut hello = vec![1, 0, 0, body.len() as u8];
        hello.extend_from_slice(&body);
        let mut handshake = new_test_handshake();
        handshake.feed_client_hello(&hello);
        assert_eq!(
            handshake.offered_cipher_suites.as_deref(),
            Some(&[0xc02f][..])
        );
        assert_eq!(
            handshake.offered_compression_methods.as_deref(),
            Some(&[0][..])
        );
        let server = make_server_hello_body(0xc013, &[0x55; 32]);
        assert!(
            matches!(feed_server_hello(&mut handshake, &server), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::IllegalParameter)
        );
    }

    #[test]
    fn server_hello_with_extended_master_secret() {
        let mut hs = new_test_handshake();
        hs.feed_client_hello(b"ch");
        let body = make_server_hello_body_with_ems(0xC02F, &[0u8; 32]);
        let record = build_handshake_message(handshake_type::SERVER_HELLO, &body);
        hs.process_handshake_record(&record).unwrap();
        assert!(hs.used_extended_master_secret());
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
        assert_eq!(
            hs.negotiated_cipher_suite().unwrap().prf_algorithm(),
            PrfAlgorithm::Sha384
        );
        let hash = transcript_hash(&hs);
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
        assert_eq!(hs.server_certificates().len(), 1);
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
        assert!(matches!(
            hs.state,
            Phase::ServerFlight(state::ServerFlight {
                step: state::ServerFlightStep::RequestOrDone {
                    exchange: state::Exchange::Ecdhe { .. },
                    ..
                },
                ..
            })
        ));
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
    fn negotiated_certificate_status_advances_to_ske() {
        let mut hs = new_test_handshake();
        let hello = make_server_hello_body_with_extensions(0xc02f, &[0x11; 32], &[(5, Vec::new())]);
        hs.process_handshake_record(&build_handshake_message(2, &hello))
            .unwrap();
        let cert = make_certificate_body(&[&[0x30, 0x00]]);
        hs.process_handshake_record(&build_handshake_message(11, &cert))
            .unwrap();
        let record = build_handshake_message(handshake_type::CERTIFICATE_STATUS, &[1, 0, 0, 1, 0]);
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
        let cr_record = build_handshake_message(0x0D, &[1, 1, 0, 2, 4, 1, 0, 0]);
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
        let mut hs = full_handshake_waiting_for_ccs();
        hs.notify_server_ccs_received();
        let result = hs.process_server_finished(&[0u8; 7]); // bad length
        assert!(result.is_err());
    }

    #[test]
    fn server_finished_verify_data_mismatch() {
        let mut hs = full_handshake_waiting_for_ccs();
        hs.notify_server_ccs_received();
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
        hs.process_handshake_record(&build_handshake_message(
            2,
            &make_server_hello_body(0xc02f, &[0x11; 32]),
        ))
        .unwrap();
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
        assert!(pending_resumption(&hs).is_none());
    }

    #[test]
    fn abbreviated_new_session_ticket() {
        let mut hs = new_test_handshake();
        hs.set_session_ticket_master_secret(vec![0xBB; 48]);
        hs.feed_client_hello(b"ch");

        let mut sh_body = make_server_hello_body(0xC02F, &[0u8; 32]);
        sh_body.extend_from_slice(&[0, 4, 0, 35, 0, 0]);
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
        assert!(hs.used_extended_master_secret());

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
        hs.process_handshake_record(&build_handshake_message(
            2,
            &make_server_hello_body(0x0035, &[0x11; 32]),
        ))
        .unwrap();

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
        assert!(pending_resumption(&hs).is_some());
        assert_eq!(pending_resumption(&hs).and_then(|r| r.used_ems), None);
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
        assert_eq!(pending_resumption(&hs).and_then(|r| r.used_ems), Some(true));

        let cert_body = make_certificate_body(&[&[0xDE, 0xAD]]);
        hs.process_handshake_record(&build_handshake_message(
            handshake_type::CERTIFICATE,
            &cert_body,
        ))
        .expect("Certificate parses");
        assert!(pending_resumption(&hs).is_none());
        assert_eq!(pending_resumption(&hs).and_then(|r| r.used_ems), None);
    }
}
