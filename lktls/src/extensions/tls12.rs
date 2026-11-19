//! Validated TLS 1.2 ServerHello results, independent of handshake orchestration.

use bytes::Buf;

use crate::crypto::tls12_cipher::{CbcMacMode, Tls12CipherSuite};
use crate::error::{AlertDescription, Result, TlsError};

pub(super) enum ServerValue<'a> {
    Ignored,
    ServerName,
    StatusRequest,
    SessionTicket,
    SecureRenegotiation,
    PointFormats,
    SignedCertificateTimestamps,
    ExtendedMasterSecret,
    EncryptThenMac,
    Alpn(&'a [u8]),
    RecordSizeLimit(u16),
}

#[derive(Default)]
pub(crate) struct ServerExtensions {
    pub(crate) extended_master_secret: bool,
    pub(crate) cbc_mac_mode: CbcMacMode,
    pub(crate) alpn: Option<String>,
    pub(crate) record_size_limit: Option<u16>,
    pub(crate) status_request: bool,
    pub(crate) session_ticket: bool,
}

impl ServerExtensions {
    pub(crate) fn parse(
        mut encoded: &[u8],
        suite: Tls12CipherSuite,
        offered: Option<&[u16]>,
        offered_alpn: Option<&[Vec<u8>]>,
    ) -> Result<Self> {
        let mut result = Self::default();
        if encoded.is_empty() {
            return Ok(result);
        }
        if encoded.remaining() < 2 || encoded.get_u16() as usize != encoded.remaining() {
            return Err(decode_error("ServerHello extension vector length mismatch"));
        }
        let mut seen = std::collections::HashSet::new();
        while !encoded.is_empty() {
            if encoded.remaining() < 4 {
                return Err(decode_error("truncated ServerHello extension header"));
            }
            let code = encoded.get_u16();
            let length = encoded.get_u16() as usize;
            if encoded.remaining() < length {
                return Err(decode_error("truncated ServerHello extension payload"));
            }
            let (payload, remaining) = encoded.split_at(length);
            encoded = remaining;
            if !seen.insert(code) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!("duplicate ServerHello extension 0x{code:04x}"),
                ));
            }
            if offered.is_some_and(|offers| !offers.contains(&code)) {
                return Err(TlsError::local_alert(
                    AlertDescription::UnsupportedExtension,
                    format!("server sent unsolicited ServerHello extension 0x{code:04x}"),
                ));
            }
            match super::registry::parse_tls12_server(code, payload)? {
                ServerValue::ExtendedMasterSecret => result.extended_master_secret = true,
                ServerValue::EncryptThenMac => {
                    if !suite.is_cbc() {
                        return Err(TlsError::local_alert(
                            AlertDescription::IllegalParameter,
                            "encrypt_then_mac requires a CBC cipher suite",
                        ));
                    }
                    result.cbc_mac_mode = CbcMacMode::EncryptThenMac;
                }
                ServerValue::Alpn(protocol) => {
                    if offered_alpn.is_some_and(|offers| !offers.iter().any(|p| p == protocol)) {
                        return Err(TlsError::local_alert(
                            AlertDescription::IllegalParameter,
                            "server selected an unoffered ALPN protocol",
                        ));
                    }
                    result.alpn = Some(String::from_utf8_lossy(protocol).into_owned());
                }
                ServerValue::RecordSizeLimit(limit) => result.record_size_limit = Some(limit),
                ServerValue::StatusRequest => result.status_request = true,
                ServerValue::SessionTicket => result.session_ticket = true,
                _ => {}
            }
        }
        Ok(result)
    }
}

pub(super) fn decode_error(message: &str) -> TlsError {
    TlsError::local_alert(AlertDescription::DecodeError, message)
}
