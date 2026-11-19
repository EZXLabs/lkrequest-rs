//! TLS Record Layer — framing and encryption/decryption of records.
//!
//! The record layer sits between the handshake/application layer and the
//! transport (TCP).  It handles:
//! - Framing: splitting data into TLS records with type/version/length headers
//! - Encryption: AEAD encryption of outgoing records
//! - Decryption: AEAD decryption of incoming records
//! - Sequence number management
//!
//! Supports both TLS 1.3 and TLS 1.2 record formats:
//! - TLS 1.3: nonce = IV XOR seq_num, outer type = APPLICATION_DATA, inner type appended
//! - TLS 1.2 GCM: nonce = implicit_iv(4) || explicit_nonce(8), original content type
//! - TLS 1.2 ChaCha20: nonce = IV XOR seq_num (like TLS 1.3), original content type

pub mod buffer;
#[cfg(test)]
mod measurement;
mod protection;
pub mod reader;
pub mod writer;
pub use protection::{ReadKeys, WriteKeys};

pub use crate::crypto::tls12_cipher::Tls12RecordCipher;

/// Observe only the explicit TLS 1.2 plaintext append, never backend movement.
#[cfg(test)]
pub(crate) fn measure_plaintext_copy(bytes: usize) {
    measurement::copied(measurement::CopySite::PlaintextSeal, bytes);
}

/// Request geometric buffer growth within the caller's budget. Existing larger
/// allocations are retained; allocator overhead and usable size are not bounded.
pub(crate) fn reserve_bounded(bytes: &mut Vec<u8>, additional: usize, limit: usize) {
    let required = bytes.len() + additional;
    if required > bytes.capacity() {
        let target = required.max(bytes.capacity().saturating_mul(2)).min(limit);
        debug_assert!(
            target >= required,
            "record growth exceeds its checked budget"
        );
        bytes.reserve_exact(target - bytes.len());
    }
}

/// Maximum TLS record payload size (2^14 = 16384 bytes).
pub const MAX_RECORD_PAYLOAD: usize = 16384;

/// Largest `TLSInnerPlaintext` a TLS 1.3 record may carry: 2^14 + 1 octets.
///
/// RFC 8446 §5.2 caps `TLSInnerPlaintext.content` at 2^14 octets and appends one
/// octet of inner content type; RFC 8449 §4 states the same total the other way
/// round — "TLS 1.3 uses a limit of 2^14+1 octets" for a value that "includes
/// the content type and padding added in TLS 1.3 (that is, the complete length
/// of TLSInnerPlaintext)".
pub const MAX_TLS13_INNER_PLAINTEXT: usize = MAX_RECORD_PAYLOAD + 1;

/// Largest expansion RFC 8446 §5.2 allows a `TLSCiphertext` to add over the
/// plaintext it protects: 256 octets, hence a wire record of at most 2^14 + 256.
pub const MAX_CIPHERTEXT_EXPANSION: usize = 256;

/// TLS 1.2 permits up to 2048 bytes of ciphertext expansion (RFC 5246 section 6.2.3).
pub const MAX_TLS12_CIPHERTEXT_EXPANSION: usize = 2048;

/// TLS record header size: ContentType (1) + Version (2) + Length (2).
pub const RECORD_HEADER_SIZE: usize = 5;

/// A parsed TLS record header.
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Content type (handshake, application_data, alert, etc.).
    pub content_type: u8,
    /// Protocol version on the wire (usually 0x0303).
    pub version: u16,
    /// Length of the record payload.
    pub length: u16,
}

impl RecordHeader {
    /// Parse a record header from exactly 5 bytes.
    pub fn from_bytes(bytes: &[u8; 5]) -> Self {
        Self {
            content_type: bytes[0],
            version: u16::from_be_bytes([bytes[1], bytes[2]]),
            length: u16::from_be_bytes([bytes[3], bytes[4]]),
        }
    }

    /// Encode the header into 5 bytes.
    pub fn to_bytes(&self) -> [u8; 5] {
        let ver = self.version.to_be_bytes();
        let len = self.length.to_be_bytes();
        [self.content_type, ver[0], ver[1], len[0], len[1]]
    }
}
