//! ServerHello message parser.
//!
//! Parses the ServerHello to extract:
//! - Selected TLS version (from `supported_versions` extension for TLS 1.3)
//! - Server random (32 bytes)
//! - Selected cipher suite
//! - Session ID (echo)
//! - Selected key share group + public key (for TLS 1.3)
//! - HelloRetryRequest detection (via special random value)

use crate::error::{AlertDescription, Result, TlsError};

/// The special ServerHello.random value that indicates a HelloRetryRequest
/// (RFC 8446 Section 4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parsed ServerHello message.
#[derive(Debug)]
pub struct ServerHello {
    /// The TLS version on the wire (always 0x0303 for TLS 1.3).
    pub legacy_version: u16,
    /// Server random (32 bytes).
    pub random: [u8; 32],
    /// Session ID echoed by server.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method (always 0 for TLS 1.3).
    pub compression_method: u8,
    /// Parsed extensions.
    pub extensions: ServerHelloExtensions,
    /// Every extension type present, in wire order.
    ///
    /// Kept verbatim (including types this parser does not otherwise care
    /// about) so the caller can enforce RFC 8446 §4.2: a server MUST NOT send
    /// an extension the client did not offer, and a client that receives one
    /// MUST abort with `unsupported_extension`. The parser cannot make that
    /// call itself — it does not know what was offered.
    pub extension_types: Vec<u16>,
    /// Whether this is a HelloRetryRequest (detected from the special random).
    pub is_hello_retry_request: bool,
}

/// Extensions extracted from the ServerHello.
#[derive(Debug, Default)]
pub struct ServerHelloExtensions {
    /// The actual negotiated version (from `supported_versions` extension).
    /// For TLS 1.3, this will be `Some(0x0304)`.
    pub supported_version: Option<u16>,
    /// Server's key share: (named_group, public_key_bytes).
    /// Present in TLS 1.3 ServerHello (not in HRR).
    pub key_share: Option<(u16, Vec<u8>)>,
    /// HRR selected group (from key_share extension in HRR — only the group, no key).
    pub selected_group: Option<u16>,
    /// Cookie extension data (from HRR).
    pub cookie: Option<Vec<u8>>,
    /// Selected PSK identity index (from `pre_shared_key` extension).
    /// Present when the server accepts a PSK offered in the ClientHello.
    pub selected_psk_identity: Option<u16>,
    /// ECH acceptance confirmation carried by HelloRetryRequest.
    pub ech_confirmation: Option<[u8; 8]>,
}

impl ServerHello {
    /// The actual negotiated TLS version.
    ///
    /// Returns the `supported_versions` extension value if present,
    /// otherwise falls back to `legacy_version`.
    pub fn negotiated_version(&self) -> u16 {
        self.extensions
            .supported_version
            .unwrap_or(self.legacy_version)
    }

    /// Whether TLS 1.3 was negotiated.
    pub fn is_tls13(&self) -> bool {
        self.negotiated_version() == 0x0304
    }
}

/// Parse a ServerHello from raw handshake payload bytes.
///
/// The input `data` starts right after the 4-byte handshake header
/// (type + 3-byte length), i.e. it begins with ProtocolVersion.
pub fn parse_server_hello(data: &[u8]) -> Result<ServerHello> {
    let mut pos = 0;

    // ProtocolVersion (2 bytes)
    if pos + 2 > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for version".to_string(),
        ));
    }
    let legacy_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes)
    if pos + 32 > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for random".to_string(),
        ));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let is_hello_retry_request = random == HRR_RANDOM;

    // Session ID (1-byte length + data)
    if pos + 1 > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for session ID length".to_string(),
        ));
    }
    let session_id_len = data[pos] as usize;
    if session_id_len > 32 {
        return Err(TlsError::local_alert(
            AlertDescription::DecodeError,
            "ServerHello session ID exceeds 32 bytes",
        ));
    }
    pos += 1;
    if pos + session_id_len > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for session ID".to_string(),
        ));
    }
    let session_id = data[pos..pos + session_id_len].to_vec();
    pos += session_id_len;

    // Cipher Suite (2 bytes)
    if pos + 2 > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for cipher suite".to_string(),
        ));
    }
    let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Compression Method (1 byte)
    if pos + 1 > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "ServerHello too short for compression method".to_string(),
        ));
    }
    let compression_method = data[pos];
    pos += 1;

    // Extensions
    let mut extensions = ServerHelloExtensions::default();
    let mut extension_types: Vec<u16> = Vec::new();
    if pos < data.len() && data.len() - pos < 2 {
        return Err(TlsError::local_alert(
            AlertDescription::DecodeError,
            "ServerHello has a truncated extensions length prefix",
        ));
    }
    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos.checked_add(ext_total).ok_or_else(|| {
            TlsError::local_alert(
                AlertDescription::DecodeError,
                "ServerHello extensions length overflow",
            )
        })?;
        if ext_end > data.len() {
            return Err(TlsError::local_alert(
                AlertDescription::DecodeError,
                "ServerHello extensions exceed message length",
            ));
        }
        if ext_end != data.len() {
            return Err(TlsError::local_alert(
                AlertDescription::DecodeError,
                "ServerHello has trailing bytes after extensions",
            ));
        }

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > ext_end {
                return Err(TlsError::local_alert(
                    AlertDescription::DecodeError,
                    "ServerHello extension exceeds extensions block",
                ));
            }
            let ext_data = &data[pos..pos + ext_len];
            pos += ext_len;

            // RFC 8446 §4.2: "There MUST NOT be more than one extension of the
            // same type in a given extension block."  This applies to every
            // ServerHello, not just a HelloRetryRequest — a duplicate is how a
            // parser and a peer end up disagreeing about which copy counted.
            if extension_types.contains(&ext_type) {
                let message = if is_hello_retry_request {
                    format!("duplicate HelloRetryRequest extension 0x{ext_type:04x}")
                } else {
                    format!("duplicate ServerHello extension 0x{ext_type:04x}")
                };
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    message,
                ));
            }
            extension_types.push(ext_type);

            match ext_type {
                // supported_versions (0x002b)
                0x002b if ext_data.len() == 2 => {
                    extensions.supported_version =
                        Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                }
                0x002b if is_hello_retry_request => {
                    return Err(TlsError::local_alert(
                        AlertDescription::DecodeError,
                        "HRR supported_versions must be exactly 2 bytes",
                    ));
                }

                // key_share (0x0033)
                0x0033 => {
                    if is_hello_retry_request {
                        // HRR key_share only contains the selected group (2 bytes)
                        if ext_data.len() != 2 {
                            return Err(TlsError::local_alert(
                                AlertDescription::DecodeError,
                                "HRR key_share must contain exactly one selected group",
                            ));
                        }
                        extensions.selected_group =
                            Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                    } else {
                        // Normal ServerHello key_share: group (2) + key_len (2) + key
                        if ext_data.len() >= 4 {
                            let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                            let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                            if 4 + key_len <= ext_data.len() {
                                let key = ext_data[4..4 + key_len].to_vec();
                                extensions.key_share = Some((group, key));
                            }
                        }
                    }
                }

                // cookie (0x002c) — only in HRR
                0x002c if is_hello_retry_request && ext_data.len() >= 2 => {
                    let cookie_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if 2 + cookie_len != ext_data.len() {
                        return Err(TlsError::local_alert(
                            AlertDescription::DecodeError,
                            "HRR cookie length does not match extension length",
                        ));
                    }
                    extensions.cookie = Some(ext_data[2..].to_vec());
                }
                0x002c if is_hello_retry_request => {
                    return Err(TlsError::local_alert(
                        AlertDescription::DecodeError,
                        "HRR cookie extension is too short",
                    ));
                }

                // pre_shared_key (0x0029) — selected PSK identity
                0x0029 if is_hello_retry_request => {
                    return Err(TlsError::local_alert(
                        AlertDescription::UnsupportedExtension,
                        "pre_shared_key is not permitted in HelloRetryRequest",
                    ));
                }
                0x0029 if ext_data.len() >= 2 => {
                    extensions.selected_psk_identity =
                        Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                }

                // encrypted_client_hello (0xFE0D) — HRR accept confirmation
                0xFE0D if is_hello_retry_request && ext_data.len() == 8 => {
                    extensions.ech_confirmation = Some(
                        ext_data
                            .try_into()
                            .expect("ECH HRR confirmation has fixed length"),
                    );
                }
                0xFE0D if is_hello_retry_request => {
                    return Err(TlsError::local_alert(
                        AlertDescription::DecodeError,
                        "HRR ECH confirmation must be exactly 8 bytes",
                    ));
                }

                _ => {
                    if is_hello_retry_request {
                        return Err(TlsError::local_alert(
                            AlertDescription::UnsupportedExtension,
                            format!(
                                "extension 0x{ext_type:04x} is not permitted in HelloRetryRequest"
                            ),
                        ));
                    }
                }
            }
        }

        if pos != ext_end {
            return Err(TlsError::local_alert(
                AlertDescription::DecodeError,
                "truncated ServerHello extension header",
            ));
        }
    } else if is_hello_retry_request {
        return Err(TlsError::local_alert(
            AlertDescription::MissingExtension,
            "HelloRetryRequest missing extensions",
        ));
    }

    Ok(ServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        extensions,
        extension_types,
        is_hello_retry_request,
    })
}

/// Extension types RFC 8446 §4.1.3 permits in an ordinary (non-HRR) ServerHello.
///
/// The ServerHello carries only what is needed to establish the cryptographic
/// context and pin the protocol version — everything else the server wants to
/// say belongs in EncryptedExtensions, where it is encrypted. A
/// HelloRetryRequest additionally allows `cookie` and the ECH
/// accept-confirmation; [`parse_server_hello`] already gates those on the HRR
/// path, so they are deliberately absent here.
pub const SERVER_HELLO_PERMITTED_EXTENSIONS: [u16; 3] = [
    0x002b, // supported_versions
    0x0033, // key_share
    0x0029, // pre_shared_key
];

/// Whether `ext_type` may appear in an ordinary (non-HRR) TLS 1.3 ServerHello.
///
/// This answers only "is this legal *here*" — it says nothing about whether the
/// client offered it. RFC 8446 §4.2 requires both, and the second half needs the
/// ClientHello, which this module does not have.
pub fn server_hello_permits_extension(ext_type: u16) -> bool {
    SERVER_HELLO_PERMITTED_EXTENSIONS.contains(&ext_type)
}

// ---------------------------------------------------------------------------
// Version detection and downgrade checks
// ---------------------------------------------------------------------------

/// RFC 8446 §4.1.3 downgrade sentinel values.
pub const DOWNGRADE_SENTINEL_TLS12: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub const DOWNGRADE_SENTINEL_TLS11: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// Whether basic SH/version parsing has reached Chromium's CCS stage.
pub(crate) fn tls13_failure_ccs_eligible(message: &[u8]) -> bool {
    // BoringSSL queues CCS after basic SH/version parsing, before HRR or
    // key-share semantics. Keep this check independent of those later rules.
    let parse = || -> Option<bool> {
        let header = message.get(..4)?;
        if header[0] != 2 {
            return Some(false);
        }
        let length =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
        let body = message.get(4..4 + length)?;
        let sid = *body.get(34)? as usize;
        if sid > 32 {
            return Some(false);
        }
        let mut position = 38 + sid;
        let prefix = body.get(position..position + 2)?;
        let length = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
        position += 2;
        if position + length != body.len() {
            return Some(false);
        }
        let mut seen = Vec::new();
        let mut tls13 = false;
        while position < body.len() {
            let header = body.get(position..position + 4)?;
            let kind = u16::from_be_bytes([header[0], header[1]]);
            let length = u16::from_be_bytes([header[2], header[3]]) as usize;
            if seen.contains(&kind) {
                return Some(false);
            }
            seen.push(kind);
            position += 4;
            let payload = body.get(position..position + length)?;
            if kind == 43 {
                if payload != [3, 4] {
                    return Some(false);
                }
                tls13 = true;
            }
            position += length;
        }
        Some(tls13)
    };
    parse().unwrap_or(false)
}

/// Quick-parse a ServerHello payload to determine the negotiated TLS version.
///
/// Returns 0x0304 for TLS 1.3, 0x0303 for TLS 1.2, etc.
pub fn detect_version_from_server_hello(payload: &[u8]) -> Result<u16> {
    detect_version_for_style(
        payload,
        crate::profile::types::TlsClientHelloStyle::Generic,
        false,
    )
    .map(|(version, _)| version)
}

pub(crate) fn detect_version_for_style(
    payload: &[u8],
    style: crate::profile::types::TlsClientHelloStyle,
    after_hrr: bool,
) -> Result<(u16, bool)> {
    if payload.len() < 4 {
        return Err(TlsError::HandshakeFailure("ServerHello too short".into()));
    }

    if payload[0] != 0x02 {
        return Err(TlsError::HandshakeFailure(format!(
            "expected ServerHello (type 0x02), got 0x{:02x}",
            payload[0]
        )));
    }

    let body = &payload[4..];

    if body.len() < 38 {
        return Err(TlsError::HandshakeFailure(
            "ServerHello body too short".into(),
        ));
    }

    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let session_id_len = body[34] as usize;
    let ext_start = 35 + session_id_len + 3;

    if ext_start > body.len() {
        return Ok((legacy_version, false));
    }

    if ext_start + 2 > body.len() {
        return Ok((legacy_version, false));
    }

    let ext_total_len = u16::from_be_bytes([body[ext_start], body[ext_start + 1]]) as usize;
    let mut offset = ext_start + 2;
    let ext_end = offset + ext_total_len;

    while offset + 4 <= ext_end && offset + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > body.len() {
            break;
        }

        if ext_type == 0x002B {
            let chromium = style == crate::profile::types::TlsClientHelloStyle::ChromiumBoringssl;
            let nss = style == crate::profile::types::TlsClientHelloStyle::FirefoxNss;
            if ext_len != 2 {
                let alert = if (chromium && after_hrr) || (nss && ext_len > 2) {
                    AlertDescription::IllegalParameter
                } else {
                    AlertDescription::DecodeError
                };
                return Err(TlsError::local_alert(
                    alert,
                    "ServerHello supported_versions must contain exactly two bytes",
                ));
            }
            let version = u16::from_be_bytes([body[offset], body[offset + 1]]);
            if (!chromium || after_hrr) && version != 0x0304 {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    "supported_versions must select TLS 1.3",
                ));
            }
            return Ok((version, true));
        }

        offset += ext_len;
    }

    Ok((legacy_version, false))
}

/// Check the ServerHello random for RFC 8446 §4.1.3 downgrade sentinels.
///
/// When a TLS 1.3-capable server negotiates TLS 1.2, it MUST set the last 8
/// bytes of `ServerHello.random` to a sentinel value.  A TLS 1.3-capable
/// client MUST check for these values and abort with `illegal_parameter` if
/// found, as it indicates a possible downgrade attack.
pub fn check_downgrade_sentinel(sh_payload: &[u8]) -> Result<()> {
    if sh_payload.len() < 4 + 2 + 32 {
        return Ok(());
    }
    let random = &sh_payload[6..38];
    let last8 = &random[24..32];

    if last8 == DOWNGRADE_SENTINEL_TLS12 || last8 == DOWNGRADE_SENTINEL_TLS11 {
        return Err(TlsError::HandshakeFailure(
            "ServerHello contains TLS 1.3 downgrade sentinel in random — \
             possible downgrade attack"
                .to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_hello_session_id_must_fit_the_32_byte_vector() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x55; 32]);
        body.push(33);
        body.extend_from_slice(&[0xa5; 33]);
        body.extend_from_slice(&[0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        assert!(
            matches!(parse_server_hello(&body), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
        );
    }

    /// Build a minimal ServerHello byte sequence for testing.
    fn build_test_server_hello(
        random: &[u8; 32],
        cipher_suite: u16,
        supported_version: Option<u16>,
        key_share: Option<(u16, &[u8])>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // ProtocolVersion = TLS 1.2
        data.extend_from_slice(&[0x03, 0x03]);
        // Random
        data.extend_from_slice(random);
        // Session ID: length=32 + 32 bytes of 0xBB
        data.push(32);
        data.extend_from_slice(&[0xBB; 32]);
        // Cipher Suite
        data.extend_from_slice(&cipher_suite.to_be_bytes());
        // Compression Method = null
        data.push(0x00);

        // Extensions
        let ext_start = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // placeholder

        let ext_data_start = data.len();

        if let Some(version) = supported_version {
            // supported_versions extension
            data.extend_from_slice(&[0x00, 0x2b]); // type
            data.extend_from_slice(&[0x00, 0x02]); // length = 2
            data.extend_from_slice(&version.to_be_bytes());
        }

        if let Some((group, key)) = key_share {
            // key_share extension
            let ext_len = (2 + 2 + key.len()) as u16;
            data.extend_from_slice(&[0x00, 0x33]); // type
            data.extend_from_slice(&ext_len.to_be_bytes());
            data.extend_from_slice(&group.to_be_bytes());
            data.extend_from_slice(&(key.len() as u16).to_be_bytes());
            data.extend_from_slice(key);
        }

        let ext_total = data.len() - ext_data_start;
        data[ext_start] = ((ext_total >> 8) & 0xff) as u8;
        data[ext_start + 1] = (ext_total & 0xff) as u8;

        data
    }

    fn build_test_hrr(extensions: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0303u16.to_be_bytes());
        data.extend_from_slice(&HRR_RANDOM);
        data.push(0);
        data.extend_from_slice(&0x1301u16.to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        data.extend_from_slice(extensions);
        data
    }

    #[test]
    fn test_parse_tls13_server_hello() {
        let random = [0xAA; 32];
        let fake_key = [0x55; 32]; // X25519 public key
        let data = build_test_server_hello(
            &random,
            0x1301, // AES_128_GCM_SHA256
            Some(0x0304),
            Some((0x001d, &fake_key)),
        );

        let sh = parse_server_hello(&data).expect("should parse");
        assert_eq!(sh.legacy_version, 0x0303);
        assert_eq!(sh.random, random);
        assert_eq!(sh.cipher_suite, 0x1301);
        assert!(!sh.is_hello_retry_request);
        assert!(sh.is_tls13());
        assert_eq!(sh.negotiated_version(), 0x0304);

        // Key share
        let (group, key) = sh.extensions.key_share.as_ref().unwrap();
        assert_eq!(*group, 0x001d);
        assert_eq!(key, &fake_key);
    }

    #[test]
    fn test_parse_hello_retry_request() {
        let mut data = Vec::new();
        // Version
        data.extend_from_slice(&[0x03, 0x03]);
        // HRR random
        data.extend_from_slice(&HRR_RANDOM);
        // Session ID: length=0
        data.push(0);
        // Cipher suite
        data.extend_from_slice(&0x1301u16.to_be_bytes());
        // Compression
        data.push(0x00);

        // Extensions
        let ext_start = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // placeholder
        let ext_data_start = data.len();

        // supported_versions
        data.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

        // key_share (HRR format: just the selected group)
        data.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x17]); // P-256

        // cookie
        let cookie_data = b"server-cookie-data";
        let cookie_ext_len = (2 + cookie_data.len()) as u16;
        data.extend_from_slice(&[0x00, 0x2c]);
        data.extend_from_slice(&cookie_ext_len.to_be_bytes());
        data.extend_from_slice(&(cookie_data.len() as u16).to_be_bytes());
        data.extend_from_slice(cookie_data);

        // encrypted_client_hello HRR accept confirmation
        let ech_confirmation = [1, 2, 3, 4, 5, 6, 7, 8];
        data.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x08]);
        data.extend_from_slice(&ech_confirmation);

        let ext_total = data.len() - ext_data_start;
        data[ext_start] = ((ext_total >> 8) & 0xff) as u8;
        data[ext_start + 1] = (ext_total & 0xff) as u8;

        let sh = parse_server_hello(&data).expect("should parse HRR");
        assert!(sh.is_hello_retry_request);
        assert!(sh.is_tls13());
        assert_eq!(sh.extensions.selected_group, Some(0x0017)); // P-256
        assert_eq!(
            sh.extensions.cookie.as_deref(),
            Some(cookie_data.as_slice())
        );
        assert_eq!(sh.extensions.ech_confirmation, Some(ech_confirmation));
        // HRR should NOT have a full key_share
        assert!(sh.extensions.key_share.is_none());
    }

    #[test]
    fn test_hrr_rejects_duplicate_extension() {
        let extensions = [
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];
        let error = parse_server_hello(&build_test_hrr(&extensions)).unwrap_err();
        assert!(error.to_string().contains("duplicate HelloRetryRequest"));
    }

    #[test]
    fn test_hrr_rejects_unknown_extension() {
        let extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x12, 0x34, 0x00, 0x00];
        let error = parse_server_hello(&build_test_hrr(&extensions)).unwrap_err();
        assert!(error
            .to_string()
            .contains("not permitted in HelloRetryRequest"));
    }

    #[test]
    fn test_hrr_rejects_invalid_ech_confirmation_length() {
        let extensions = [
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0xfe, 0x0d, 0x00, 0x07, 1, 2, 3, 4, 5, 6, 7,
        ];
        let error = parse_server_hello(&build_test_hrr(&extensions)).unwrap_err();
        assert!(error.to_string().contains("exactly 8 bytes"));
    }

    /// Build a non-HRR ServerHello carrying a caller-supplied extension block.
    fn build_test_server_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&[0xAA; 32]);
        data.push(0);
        data.extend_from_slice(&0x1301u16.to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        data.extend_from_slice(extensions);
        data
    }

    #[test]
    fn compatibility_ccs_phase_depends_on_framing_not_hrr_payload_rules() {
        let extensions = [0, 43, 0, 2, 3, 4, 0, 51, 0, 3, 0, 24, 0xa5];
        let body = build_test_hrr(&extensions);
        let wrap = |body: &[u8]| {
            let mut message = vec![2, 0, 0, body.len() as u8];
            message.extend_from_slice(body);
            message
        };
        assert!(tls13_failure_ccs_eligible(&wrap(&body)));
        assert!(
            matches!(parse_server_hello(&body), Err(TlsError::LocalAlert { alert, .. })
            if alert.description == AlertDescription::DecodeError)
        );
        let mut outside = body.clone();
        outside.push(0xa5);
        assert!(!tls13_failure_ccs_eligible(&wrap(&outside)));
        let inside = build_test_server_hello_with_extensions(&[0, 43, 0, 2, 3, 4, 0xa5]);
        assert!(!tls13_failure_ccs_eligible(&wrap(&inside)));
        let duplicate =
            build_test_server_hello_with_extensions(&[0, 43, 0, 2, 3, 4, 0, 43, 0, 2, 3, 4]);
        assert!(!tls13_failure_ccs_eligible(&wrap(&duplicate)));
        let version = build_test_server_hello_with_extensions(&[0, 43, 0, 3, 3, 4, 0]);
        assert!(!tls13_failure_ccs_eligible(&wrap(&version)));
        assert!(!tls13_failure_ccs_eligible(&[]));
    }

    #[test]
    fn server_hello_extension_container_must_be_fully_consumed() {
        let extensions = [0, 43, 0, 2, 3, 4];
        for retry in [false, true] {
            for inside in [false, true] {
                for tail_len in 1..=3 {
                    let mut body = if retry {
                        build_test_hrr(&extensions)
                    } else {
                        build_test_server_hello_with_extensions(&extensions)
                    };
                    let ext_length_pos = 38 + body[34] as usize;
                    body.extend_from_slice(&[0xa5; 3][..tail_len]);
                    if inside {
                        body[ext_length_pos..ext_length_pos + 2]
                            .copy_from_slice(&((extensions.len() + tail_len) as u16).to_be_bytes());
                    }
                    assert!(
                        matches!(parse_server_hello(&body),
                        Err(TlsError::LocalAlert { alert, .. })
                        if alert.description == AlertDescription::DecodeError),
                        "retry={retry} inside={inside} tail_len={tail_len}"
                    );
                }
            }
        }
    }

    #[test]
    fn legacy_server_hello_allows_no_extensions_but_not_half_a_length_prefix() {
        let mut body = build_test_server_hello_with_extensions(&[]);
        body.truncate(body.len() - 2);
        assert!(parse_server_hello(&body).is_ok());
        body.push(0);
        assert!(matches!(parse_server_hello(&body),
            Err(TlsError::LocalAlert { alert, .. })
            if alert.description == AlertDescription::DecodeError));
    }

    #[test]
    fn test_server_hello_rejects_duplicate_extension() {
        // Two supported_versions extensions in an ordinary ServerHello.
        let extensions = [
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];
        let error =
            parse_server_hello(&build_test_server_hello_with_extensions(&extensions)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate ServerHello extension"),
            "expected duplicate-extension rejection, got: {error}"
        );
        assert_eq!(
            error.as_alert().map(|alert| alert.description),
            Some(AlertDescription::IllegalParameter),
        );
    }

    #[test]
    fn test_server_hello_rejects_duplicate_key_share() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        for _ in 0..2 {
            extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x02]);
            extensions.extend_from_slice(&[0xAB, 0xCD]);
        }
        let error =
            parse_server_hello(&build_test_server_hello_with_extensions(&extensions)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate ServerHello extension"),
            "expected duplicate-extension rejection, got: {error}"
        );
    }

    #[test]
    fn test_server_hello_records_extension_types_in_wire_order() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        // An extension the parser does not otherwise model must still be recorded.
        extensions.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        let sh = parse_server_hello(&build_test_server_hello_with_extensions(&extensions))
            .expect("should parse");
        assert_eq!(sh.extension_types, vec![0x002b, 0x0010]);
    }

    #[test]
    fn test_server_hello_permits_only_cryptographic_context_extensions() {
        for permitted in SERVER_HELLO_PERMITTED_EXTENSIONS {
            assert!(server_hello_permits_extension(permitted));
        }
        // ALPN, cookie and ECH belong to EncryptedExtensions / HRR, not here.
        assert!(!server_hello_permits_extension(0x0010));
        assert!(!server_hello_permits_extension(0x002c));
        assert!(!server_hello_permits_extension(0xFE0D));
    }

    #[test]
    fn test_parse_tls12_server_hello() {
        let random = [0x33; 32];
        let data = build_test_server_hello(
            &random, 0xc02f, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
            None,   // No supported_versions = TLS 1.2
            None,   // No key_share
        );

        let sh = parse_server_hello(&data).expect("should parse");
        assert_eq!(sh.legacy_version, 0x0303);
        assert_eq!(sh.cipher_suite, 0xc02f);
        assert!(!sh.is_tls13());
        assert_eq!(sh.negotiated_version(), 0x0303); // falls back to legacy
        assert!(sh.extensions.key_share.is_none());
    }

    #[test]
    fn test_parse_too_short() {
        let result = parse_server_hello(&[0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_id_echo() {
        let random = [0x11; 32];
        let data = build_test_server_hello(&random, 0x1301, Some(0x0304), None);
        let sh = parse_server_hello(&data).unwrap();
        assert_eq!(sh.session_id.len(), 32);
        assert_eq!(sh.session_id, vec![0xBB; 32]);
    }
}
