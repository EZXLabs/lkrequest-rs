//! Record Size Limit extension — type 0x001c.
//!
//! Indicates the maximum record size the endpoint is willing to receive
//! (RFC 8449).  Used primarily by Firefox.
//!
//! The value is *directional*: RFC 8449 §4 says "The record size limit only
//! applies to records sent toward the endpoint that advertises the limit."  So
//! the value we put in the ClientHello constrains the server, and the value the
//! server sends back — in EncryptedExtensions under TLS 1.3, in the ServerHello
//! under TLS 1.2 — constrains us.  Both directions are enforced:
//! [`crate::record::writer::RecordWriter::set_peer_record_size_limit`] shrinks
//! the records we send, and
//! [`crate::record::reader::RecordReader::set_own_record_size_limit`] rejects an
//! inbound record over the limit we advertised with a `record_overflow` alert,
//! as RFC 8449 §4 requires.

use super::Extension;
use crate::error::{AlertDescription, Result, TlsError};

/// Smallest value RFC 8449 §4 permits in a `record_size_limit` extension.
///
/// "Endpoints MUST NOT send a 'record_size_limit' extension with a value
/// smaller than 64.  An endpoint MUST treat receipt of a smaller value as a
/// fatal error and generate an 'illegal_parameter' alert."
pub const MIN_RECORD_SIZE_LIMIT: u16 = 64;

/// Protocol-defined maximum for TLS 1.2 and earlier: 2^14 octets.
pub const MAX_RECORD_SIZE_LIMIT_TLS12: u16 = 16384;

/// Protocol-defined maximum for TLS 1.3: 2^14 + 1 octets.
///
/// One octet more than TLS 1.2 because the TLS 1.3 limit counts the whole
/// `TLSInnerPlaintext`, which appends a content-type octet to the plaintext.
pub const MAX_RECORD_SIZE_LIMIT_TLS13: u16 = 16385;

/// Record Size Limit extension.
pub struct RecordSizeLimit {
    /// The maximum record size in bytes (big-endian u16 on the wire).
    pub limit: u16,
}

impl Extension for RecordSizeLimit {
    fn extension_type(&self) -> u16 {
        0x001c
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.limit.to_be_bytes());
    }
}

/// Parse a Record Size Limit value from extension payload bytes.
///
/// Lenient: returns the first two octets without validating them.  Use
/// [`parse_peer_record_size_limit`] for anything received from a peer.
pub fn parse_record_size_limit(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

/// Parse and validate a `record_size_limit` value received from a peer.
///
/// RFC 8449 §4 makes exactly one value range a fatal error: "Endpoints MUST NOT
/// send a 'record_size_limit' extension with a value smaller than 64.  An
/// endpoint MUST treat receipt of a smaller value as a fatal error and generate
/// an 'illegal_parameter' alert."
///
/// An over-large value is deliberately *not* an error here.  RFC 8449 only says
/// a client "MAY abort the handshake with an 'illegal_parameter' alert" in that
/// case, while the enforcement rule is unconditional: "Even if a larger record
/// size limit is provided by a peer, an endpoint MUST NOT send records larger
/// than the protocol-defined limit."  So an over-large value is accepted and
/// clamped by the record writer rather than killing an otherwise fine
/// connection — a peer that says "16385" under TLS 1.2 is being sloppy, not
/// hostile.
pub fn parse_peer_record_size_limit(data: &[u8]) -> Result<u16> {
    if data.len() != 2 {
        return Err(TlsError::local_alert(
            AlertDescription::DecodeError,
            format!(
                "record_size_limit must be exactly 2 bytes, got {}",
                data.len()
            ),
        ));
    }
    let limit = u16::from_be_bytes([data[0], data[1]]);
    if limit < MIN_RECORD_SIZE_LIMIT {
        return Err(TlsError::local_alert(
            AlertDescription::IllegalParameter,
            format!(
                "peer record_size_limit {limit} is below the RFC 8449 minimum of \
                 {MIN_RECORD_SIZE_LIMIT}"
            ),
        ));
    }
    Ok(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_record_size_limit() {
        let ext = RecordSizeLimit { limit: 16385 };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(
            buf,
            [
                0x00, 0x1c, // type
                0x00, 0x02, // extension length = 2
                0x40, 0x01, // 16385 in big-endian
            ]
        );
    }

    #[test]
    fn test_parse_record_size_limit() {
        assert_eq!(parse_record_size_limit(&[0x40, 0x01]), Some(16385));
        assert_eq!(parse_record_size_limit(&[0x00]), None);
        assert_eq!(parse_record_size_limit(&[]), None);
    }

    #[test]
    fn peer_limit_accepts_legal_values() {
        assert_eq!(parse_peer_record_size_limit(&[0x00, 0x40]).unwrap(), 64);
        assert_eq!(parse_peer_record_size_limit(&[0x02, 0x00]).unwrap(), 512);
        assert_eq!(
            parse_peer_record_size_limit(&[0x40, 0x00]).unwrap(),
            MAX_RECORD_SIZE_LIMIT_TLS12
        );
        assert_eq!(
            parse_peer_record_size_limit(&[0x40, 0x01]).unwrap(),
            MAX_RECORD_SIZE_LIMIT_TLS13
        );
    }

    /// RFC 8449 §4: a value below 64 is a fatal `illegal_parameter`.
    #[test]
    fn peer_limit_below_64_is_illegal_parameter() {
        for raw in [0u16, 1, 63] {
            let err = parse_peer_record_size_limit(&raw.to_be_bytes())
                .expect_err("a record_size_limit below 64 must be rejected");
            let description = err.as_alert().map(|a| a.description);
            assert_eq!(
                description,
                Some(AlertDescription::IllegalParameter),
                "value {raw} must be rejected with illegal_parameter, got {description:?}"
            );
        }
    }

    #[test]
    fn peer_limit_wrong_length_is_decode_error() {
        for data in [&[][..], &[0x40][..], &[0x40, 0x00, 0x00][..]] {
            let err = parse_peer_record_size_limit(data)
                .expect_err("a malformed record_size_limit must be rejected");
            assert_eq!(
                err.as_alert().map(|a| a.description),
                Some(AlertDescription::DecodeError),
                "payload {data:?} must be a decode_error"
            );
        }
    }

    /// An over-large value is tolerated at parse time — the writer clamps it.
    #[test]
    fn peer_limit_above_protocol_maximum_is_accepted() {
        assert_eq!(parse_peer_record_size_limit(&[0xff, 0xff]).unwrap(), 65535);
    }
}
