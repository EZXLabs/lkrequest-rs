//! TLS Record writer — encrypts and frames outgoing TLS records.
//!
//! The `RecordWriter` takes application data and handshake messages, wraps them
//! in TLS record framing, and optionally encrypts them.  Before keys are
//! established, records are emitted in plaintext.  After key installation via
//! [`RecordWriter::set_keys`] or [`RecordWriter::set_tls12_keys`], all
//! outgoing records are AEAD-encrypted.
//!
//! Supports two flush strategies:
//! - **Immediate**: each record is returned immediately (default).
//! - **Coalesce**: multiple records are buffered and returned together on
//!   [`RecordWriter::flush`], ensuring critical messages (e.g. ClientHello)
//!   are sent in a single TCP segment.
//!
//! Application data is chunked at [`MAX_RECORD_PAYLOAD`] unless the peer asked
//! for something smaller with the RFC 8449 `record_size_limit` extension — see
//! [`RecordWriter::set_peer_record_size_limit`].

use super::{RecordHeader, Tls12RecordCipher, MAX_RECORD_PAYLOAD};
use crate::crypto::aead::Aead;
use crate::error::{Result, TlsError};
use crate::handshake::content_type;

/// Flush strategy for record output.
///
/// Controls whether records are emitted immediately or coalesced into
/// fewer TCP segments for better fingerprint control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlushStrategy {
    /// Emit each record immediately.
    #[default]
    Immediate,
    /// Coalesce multiple small records before flushing.
    /// This ensures critical messages (like ClientHello) are sent in a single
    /// TCP segment, avoiding middlebox detection of TLS record splitting.
    Coalesce,
}

/// Writes TLS records, encrypting them once keys are established.
pub struct RecordWriter {
    /// Write sequence number (for AEAD nonce construction).
    seq_num: u64,
    /// TLS 1.3 AEAD encryption key + IV (None before keys are established).
    aead: Option<Aead>,
    /// TLS 1.2 record cipher (None if using TLS 1.3 or plaintext).
    tls12_cipher: Option<Tls12RecordCipher>,
    /// Flush strategy.
    flush_strategy: FlushStrategy,
    /// Internal buffer for coalesced records.
    coalesce_buf: Vec<u8>,
    /// Whether the first record (ClientHello) has been sent.
    /// RFC 8446 Section 5.1: initial ClientHello uses version 0x0301,
    /// all subsequent records use 0x0303.
    first_record_sent: bool,
    /// The peer's RFC 8449 `record_size_limit`, if it sent one.
    ///
    /// `None` — the overwhelmingly common case, since neither Chrome nor any
    /// mainstream server advertises a reduced limit — means "chunk at
    /// `MAX_RECORD_PAYLOAD`", i.e. byte-for-byte the behaviour that predates
    /// this field.
    peer_record_size_limit: Option<u16>,
}

impl RecordWriter {
    /// Create a new record writer (plaintext mode — no encryption).
    pub fn new() -> Self {
        Self {
            seq_num: 0,
            aead: None,
            tls12_cipher: None,
            flush_strategy: FlushStrategy::Immediate,
            coalesce_buf: Vec::new(),
            first_record_sent: false,
            peer_record_size_limit: None,
        }
    }

    /// Honour the peer's RFC 8449 `record_size_limit`.
    ///
    /// The value is the peer's *receive* limit, so it bounds the records **we**
    /// send: RFC 8449 §4, "The value of RecordSizeLimit is the maximum size of
    /// record in octets that the endpoint is willing to receive." A peer that
    /// never sent the extension leaves this `None` and nothing changes.
    ///
    /// Call this once the peer's value is known (TLS 1.3: EncryptedExtensions;
    /// TLS 1.2: ServerHello). It only ever shrinks records, never grows them —
    /// see [`Self::max_plaintext_chunk`].
    pub fn set_peer_record_size_limit(&mut self, limit: Option<u16>) {
        self.peer_record_size_limit = limit;
    }

    /// The peer's `record_size_limit`, if one was negotiated.
    pub fn peer_record_size_limit(&self) -> Option<u16> {
        self.peer_record_size_limit
    }

    /// The largest plaintext this writer will place in a single record of
    /// `content_type`.
    ///
    /// Three RFC 8449 §4 rules combine here:
    ///
    /// 1. *Scope.* "Unprotected messages are not subject to this limit." Before
    ///    keys are installed there is nothing to limit, so the plaintext
    ///    ClientHello flight is untouched.
    /// 2. *Units.* "This value is the length of the plaintext of a protected
    ///    record.  The value includes the content type and padding added in TLS
    ///    1.3 (that is, the complete length of TLSInnerPlaintext).  In TLS 1.2
    ///    and earlier, the limit covers all input to compression and encryption
    ///    (that is, the data that ultimately produces
    ///    TLSCiphertext.fragment)." TLS 1.3 appends a content-type octet inside
    ///    the encrypted record, so the usable plaintext is `limit - 1`; TLS 1.2
    ///    has no such octet and the usable plaintext is `limit` exactly.
    /// 3. *Ceiling.* "Even if a larger record size limit is provided by a peer,
    ///    an endpoint MUST NOT send records larger than the protocol-defined
    ///    limit." A peer value above 2^14 therefore cannot raise our records
    ///    above [`MAX_RECORD_PAYLOAD`].
    ///
    /// The limit is applied to application data only. RFC 8449 phrases the
    /// scope as "application data and the protected handshake message", but our
    /// protected handshake records are a fingerprint surface that must stay
    /// byte-identical to the browser we emulate, and they are already far below
    /// any realistic limit (a client Finished is ~36 bytes).
    pub fn max_plaintext_chunk(&self, record_content_type: u8) -> usize {
        let Some(limit) = self.peer_record_size_limit else {
            return MAX_RECORD_PAYLOAD;
        };
        if record_content_type != content_type::APPLICATION_DATA {
            return MAX_RECORD_PAYLOAD;
        }

        let plaintext_bound = if self.aead.is_some() {
            // TLS 1.3: the limit covers TLSInnerPlaintext = payload || type.
            usize::from(limit).saturating_sub(1)
        } else if self.tls12_cipher.is_some() {
            // TLS 1.2: the limit covers the payload exactly.
            usize::from(limit)
        } else {
            // Unprotected — not subject to the limit.
            return MAX_RECORD_PAYLOAD;
        };

        // Never grow past the protocol maximum, and never reach zero (a
        // zero-sized chunk would not make progress).
        plaintext_bound.clamp(1, MAX_RECORD_PAYLOAD)
    }

    /// Mark that the initial record has already been sent.
    ///
    /// Subsequent plaintext records will use version 0x0303 instead of 0x0301.
    /// Used for CH2 after HRR (the initial ClientHello was already sent).
    pub fn mark_post_initial(&mut self) {
        self.first_record_sent = true;
    }

    /// Set the flush strategy.
    pub fn set_flush_strategy(&mut self, strategy: FlushStrategy) {
        self.flush_strategy = strategy;
    }

    /// Flush any coalesced records, returning all buffered bytes.
    ///
    /// In `Immediate` mode this always returns empty.
    /// In `Coalesce` mode this returns any buffered records.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.coalesce_buf)
    }

    /// Install TLS 1.3 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_keys(&mut self, aead: Aead) {
        self.aead = Some(aead);
        self.tls12_cipher = None;
        self.seq_num = 0;
    }

    /// Install TLS 1.2 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        self.tls12_cipher = Some(cipher);
        self.aead = None;
        self.seq_num = 0;
    }

    /// Wrap data into one or more TLS records.
    ///
    /// Before keys are established, this produces plaintext records.
    /// After keys are set, the payload is AEAD-encrypted per the negotiated version.
    ///
    /// For large payloads, the data is split into multiple records of at most
    /// [`Self::max_plaintext_chunk`] bytes each — `MAX_RECORD_PAYLOAD` unless
    /// the peer negotiated a smaller RFC 8449 `record_size_limit`.
    ///
    /// In `Immediate` mode, returns all record bytes concatenated.
    /// In `Coalesce` mode, buffers records internally — call [`Self::flush`] to retrieve.
    pub fn write_record(&mut self, content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        if payload.is_empty() {
            let record = self.encode_single_record(content_type, &[])?;
            match self.flush_strategy {
                FlushStrategy::Immediate => output.extend_from_slice(&record),
                FlushStrategy::Coalesce => self.coalesce_buf.extend_from_slice(&record),
            }
            return Ok(output);
        }

        // Split into MAX_RECORD_PAYLOAD-sized chunks, or smaller if the peer
        // advertised an RFC 8449 `record_size_limit`.
        for chunk in payload.chunks(self.max_plaintext_chunk(content_type)) {
            let record = self.encode_single_record(content_type, chunk)?;
            match self.flush_strategy {
                FlushStrategy::Immediate => output.extend_from_slice(&record),
                FlushStrategy::Coalesce => self.coalesce_buf.extend_from_slice(&record),
            }
        }

        Ok(output)
    }

    /// Encode a single TLS record.
    fn encode_single_record(&mut self, actual_content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if self.tls12_cipher.is_some() {
            self.encode_tls12_encrypted_record(actual_content_type, payload)
        } else if self.aead.is_some() {
            self.encode_tls13_encrypted_record(actual_content_type, payload)
        } else {
            self.encode_plaintext_record(actual_content_type, payload)
        }
    }

    /// Encode a plaintext (unencrypted) TLS record.
    fn encode_plaintext_record(&mut self, ct: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_RECORD_PAYLOAD {
            return Err(TlsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "record payload too large",
            )));
        }

        // RFC 8446 Section 5.1: initial ClientHello MAY use 0x0301,
        // all subsequent records MUST use 0x0303.
        let version = if !self.first_record_sent {
            self.first_record_sent = true;
            0x0301 // TLS 1.0 for initial ClientHello (compat)
        } else {
            0x0303 // TLS 1.2 for all subsequent records
        };

        let header = RecordHeader {
            content_type: ct,
            version,
            length: payload.len() as u16,
        };

        let mut record = Vec::with_capacity(5 + payload.len());
        record.extend_from_slice(&header.to_bytes());
        record.extend_from_slice(payload);
        Ok(record)
    }

    /// Encode a TLS 1.3 encrypted record.
    ///
    /// Structure:
    /// - Header: content_type=APPLICATION_DATA, version=0x0303, length
    /// - Encrypted payload: [actual_payload + inner_content_type] encrypted with AEAD
    ///
    /// The inner content type is appended to the plaintext before encryption,
    /// and the outer content type is always APPLICATION_DATA (0x17).
    fn encode_tls13_encrypted_record(
        &mut self,
        actual_content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = self.aead.as_ref().unwrap();
        // Build inner plaintext: payload + content_type byte
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(actual_content_type); // TLS 1.3 inner content type

        // The encrypted length = inner plaintext length + AEAD tag (16 bytes)
        let encrypted_len = inner.len() + aead.algorithm().tag_len();

        // Build the record header (used as AAD)
        let header = RecordHeader {
            content_type: content_type::APPLICATION_DATA, // always 0x17 on wire
            version: 0x0303,                              // TLS 1.2 on wire
            length: encrypted_len as u16,
        };
        let header_bytes = header.to_bytes();

        // Encrypt with AAD = record header
        let ciphertext = aead.encrypt(self.seq_num, &header_bytes, &inner)?;
        self.seq_num = self
            .seq_num
            .checked_add(1)
            .ok_or_else(|| TlsError::CryptoError("write sequence number overflow".to_string()))?;

        // Assemble: header + ciphertext
        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.extend_from_slice(&header_bytes);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// Encode a TLS 1.2 encrypted record.
    ///
    /// Key differences from TLS 1.3:
    /// - Outer content type is the ORIGINAL type (not APPLICATION_DATA)
    /// - No inner content type byte
    /// - AAD = seq_num(8) + content_type(1) + version(2) + plaintext_length(2)
    /// - GCM: 8-byte explicit nonce prepended to ciphertext
    /// - ChaCha20: no explicit nonce (nonce = IV XOR seq_num)
    fn encode_tls12_encrypted_record(
        &mut self,
        actual_content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = self.tls12_cipher.as_ref().unwrap();

        // TLS 1.2 AAD: seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
        aad[8] = actual_content_type;
        aad[9] = 0x03;
        aad[10] = 0x03; // version 0x0303
        let payload_len = payload.len() as u16;
        aad[11] = (payload_len >> 8) as u8;
        aad[12] = payload_len as u8;

        let ciphertext = match cipher {
            Tls12RecordCipher::Gcm(gcm) => {
                // GCM: returns explicit_nonce(8) + encrypted + tag(16)
                gcm.encrypt(self.seq_num, &aad, payload)?
            }
            Tls12RecordCipher::Chacha20(chacha) => {
                // ChaCha20: returns encrypted + tag(16), no explicit nonce
                chacha.encrypt(self.seq_num, &aad, payload)?
            }
            Tls12RecordCipher::Cbc(cbc) => {
                // CBC: returns iv(16) + encrypted(plaintext + mac + padding)
                cbc.encrypt(self.seq_num, &aad, payload)?
            }
        };
        self.seq_num = self
            .seq_num
            .checked_add(1)
            .ok_or_else(|| TlsError::CryptoError("write sequence number overflow".to_string()))?;

        // Record header with original content type
        let header = RecordHeader {
            content_type: actual_content_type,
            version: 0x0303,
            length: ciphertext.len() as u16,
        };
        let header_bytes = header.to_bytes();

        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.extend_from_slice(&header_bytes);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
}

impl Default for RecordWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{Aead as AeadCipher, AeadAlgorithm};
    use crate::crypto::tls12_cipher::Tls12GcmCipher;
    use crate::record::reader::RecordReader;

    #[test]
    fn test_write_plaintext_record() {
        let mut writer = RecordWriter::new();
        let record = writer.write_record(0x16, b"ClientHello").unwrap();

        // Header: type=0x16, version=0x0301, length=11
        assert_eq!(record[0], 0x16);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x01);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 11);
        assert_eq!(&record[5..], b"ClientHello");
    }

    #[test]
    fn test_write_empty_record() {
        let mut writer = RecordWriter::new();
        let record = writer.write_record(0x14, &[]).unwrap(); // CCS
        assert_eq!(record.len(), 5); // just the header
        assert_eq!(record[0], 0x14);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 0);
    }

    #[test]
    fn test_tls13_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        let plaintext = b"secret handshake data";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Outer content type should be APPLICATION_DATA (0x17)
        assert_eq!(record[0], 0x17);
        // Outer version should be 0x0303
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);

        // Decrypt with a reader
        let mut reader = RecordReader::new();
        reader.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // inner content type = handshake
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_tls12_gcm_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let implicit_iv = [0x01, 0x02, 0x03, 0x04];

        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let plaintext = b"Hello TLS 1.2 GCM!";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Outer content type should be HANDSHAKE (0x16) — not APPLICATION_DATA
        assert_eq!(record[0], 0x16);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);

        // Record length = 8 (explicit nonce) + payload_len + 16 (tag)
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record_len, 8 + plaintext.len() + 16);

        // Decrypt with a TLS 1.2 reader
        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // original content type preserved
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_large_payload_splits() {
        let mut writer = RecordWriter::new();
        // Payload larger than MAX_RECORD_PAYLOAD
        let large = vec![0xAA; MAX_RECORD_PAYLOAD + 100];
        let records = writer.write_record(0x17, &large).unwrap();

        // Should produce 2 records
        // First record: header (5) + MAX_RECORD_PAYLOAD
        let first_len = 5 + MAX_RECORD_PAYLOAD;
        assert_eq!(records[0], 0x17);
        assert_eq!(
            u16::from_be_bytes([records[3], records[4]]),
            MAX_RECORD_PAYLOAD as u16
        );

        // Second record at offset first_len
        assert_eq!(records[first_len], 0x17);
        assert_eq!(
            u16::from_be_bytes([records[first_len + 3], records[first_len + 4]]),
            100
        );
    }

    // -----------------------------------------------------------------------
    // RFC 8449 `record_size_limit` enforcement
    // -----------------------------------------------------------------------

    const TAG_LEN: usize = 16;
    /// TLS 1.2 AES-GCM adds an 8-byte explicit nonce ahead of the ciphertext.
    const TLS12_GCM_OVERHEAD: usize = 8 + TAG_LEN;

    /// Split a concatenated record stream into `(content_type, payload_len)`.
    fn record_frames(stream: &[u8]) -> Vec<(u8, usize)> {
        let mut frames = Vec::new();
        let mut pos = 0;
        while pos + 5 <= stream.len() {
            let ct = stream[pos];
            let len = u16::from_be_bytes([stream[pos + 3], stream[pos + 4]]) as usize;
            frames.push((ct, len));
            pos += 5 + len;
        }
        assert_eq!(
            pos,
            stream.len(),
            "record stream must end exactly on a record boundary"
        );
        frames
    }

    fn tls13_writer(limit: Option<u16>) -> RecordWriter {
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_keys(
            AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[0x42u8; 16], &[0x01u8; 12]).unwrap(),
        );
        writer.set_peer_record_size_limit(limit);
        writer
    }

    fn tls12_writer(limit: Option<u16>) -> RecordWriter {
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&[0x42u8; 16], &[0x01, 0x02, 0x03, 0x04], false).unwrap(),
        ));
        writer.set_peer_record_size_limit(limit);
        writer
    }

    /// A peer limit below the protocol maximum must actually shrink the
    /// records we emit, and the data must still round-trip.
    #[test]
    fn peer_limit_shrinks_tls13_application_records() {
        let mut writer = tls13_writer(Some(512));
        let payload: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let stream = writer
            .write_record(content_type::APPLICATION_DATA, &payload)
            .unwrap();

        let frames = record_frames(&stream);
        // Usable plaintext per record = 512 - 1 (content-type octet) = 511.
        // 2000 = 511 + 511 + 511 + 467.
        assert_eq!(
            frames.len(),
            4,
            "2000 bytes at 511/record must be 4 records"
        );
        for (index, (ct, len)) in frames.iter().enumerate() {
            assert_eq!(*ct, content_type::APPLICATION_DATA);
            let inner_plaintext = len - TAG_LEN;
            assert!(
                inner_plaintext <= 512,
                "record {index}: TLSInnerPlaintext {inner_plaintext} exceeds the peer's limit of 512"
            );
        }
        assert_eq!(frames[0].1, 511 + 1 + TAG_LEN);
        assert_eq!(frames[3].1, 467 + 1 + TAG_LEN);

        let mut reader = RecordReader::new();
        reader.set_keys(
            AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[0x42u8; 16], &[0x01u8; 12]).unwrap(),
        );
        reader.feed(&stream);
        let mut reassembled = Vec::new();
        while let Some(rec) = reader.next_record().unwrap() {
            assert_eq!(rec.content_type, content_type::APPLICATION_DATA);
            reassembled.extend_from_slice(&rec.payload);
        }
        assert_eq!(reassembled, payload, "split records must still round-trip");
    }

    /// RFC 8449 §4: under TLS 1.3 the limit is the length of TLSInnerPlaintext,
    /// which includes the appended content-type octet — so the usable
    /// application plaintext is `limit - 1`. TLS 1.2 has no such octet and gets
    /// the full `limit`.
    #[test]
    fn tls13_limit_reserves_the_content_type_octet() {
        for limit in [64u16, 512, 1024, 16385] {
            let tls13 = tls13_writer(Some(limit));
            let tls12 = tls12_writer(Some(limit));
            assert_eq!(
                tls13.max_plaintext_chunk(content_type::APPLICATION_DATA),
                (usize::from(limit) - 1).min(MAX_RECORD_PAYLOAD),
                "TLS 1.3 must reserve one octet of a {limit}-octet limit for the content type"
            );
            assert_eq!(
                tls12.max_plaintext_chunk(content_type::APPLICATION_DATA),
                usize::from(limit).min(MAX_RECORD_PAYLOAD),
                "TLS 1.2 must use the whole {limit}-octet limit for plaintext"
            );
        }

        // On the wire: exactly `limit` bytes of application data must not fit
        // in one TLS 1.3 record, because of that content-type octet.
        let mut writer = tls13_writer(Some(64));
        let stream = writer
            .write_record(content_type::APPLICATION_DATA, &[0xABu8; 64])
            .unwrap();
        let frames = record_frames(&stream);
        assert_eq!(
            frames.len(),
            2,
            "64 bytes under a 64-octet TLS 1.3 limit must split (63 + 1)"
        );
        assert_eq!(frames[0].1, 63 + 1 + TAG_LEN);
        assert_eq!(frames[1].1, 1 + 1 + TAG_LEN);

        // The same 64 bytes fit in a single TLS 1.2 record.
        let mut writer12 = tls12_writer(Some(64));
        let stream12 = writer12
            .write_record(content_type::APPLICATION_DATA, &[0xABu8; 64])
            .unwrap();
        let frames12 = record_frames(&stream12);
        assert_eq!(
            frames12.len(),
            1,
            "64 bytes fit one TLS 1.2 record at limit 64"
        );
        assert_eq!(frames12[0].1, 64 + TLS12_GCM_OVERHEAD);
    }

    #[test]
    fn tls12_peer_limit_bounds_the_whole_plaintext() {
        let mut writer = tls12_writer(Some(100));
        let payload = vec![0x7Eu8; 250];
        let stream = writer
            .write_record(content_type::APPLICATION_DATA, &payload)
            .unwrap();
        let frames = record_frames(&stream);
        assert_eq!(frames.len(), 3, "250 bytes at 100/record must be 3 records");
        assert_eq!(frames[0].1, 100 + TLS12_GCM_OVERHEAD);
        assert_eq!(frames[1].1, 100 + TLS12_GCM_OVERHEAD);
        assert_eq!(frames[2].1, 50 + TLS12_GCM_OVERHEAD);
    }

    /// With no peer limit, every emitted byte must be exactly what the writer
    /// produced before RFC 8449 support existed.
    #[test]
    fn without_a_peer_limit_output_is_unchanged() {
        let payload = vec![0x5Au8; MAX_RECORD_PAYLOAD + 100];

        // A fresh writer must not be limited by anything.
        let fresh = RecordWriter::new();
        assert_eq!(fresh.peer_record_size_limit(), None);
        for ct in [
            content_type::APPLICATION_DATA,
            content_type::HANDSHAKE,
            content_type::ALERT,
            content_type::CHANGE_CIPHER_SPEC,
        ] {
            assert_eq!(
                fresh.max_plaintext_chunk(ct),
                MAX_RECORD_PAYLOAD,
                "content type 0x{ct:02x} must chunk at the protocol maximum"
            );
        }

        // Plaintext framing, checked against a hand-built expected byte stream.
        let mut plain = RecordWriter::new();
        plain.mark_post_initial();
        let actual = plain
            .write_record(content_type::APPLICATION_DATA, &payload)
            .unwrap();
        let mut expected = Vec::new();
        for chunk in payload.chunks(MAX_RECORD_PAYLOAD) {
            expected.push(content_type::APPLICATION_DATA);
            expected.extend_from_slice(&[0x03, 0x03]);
            expected.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            expected.extend_from_slice(chunk);
        }
        assert_eq!(actual, expected, "plaintext record framing must not change");

        // Encrypted framing: an untouched writer and one explicitly told there
        // is no limit must agree byte for byte, and split at 2^14.
        let untouched = tls13_writer(None)
            .write_record(content_type::APPLICATION_DATA, &payload)
            .unwrap();
        let mut explicit_none = tls13_writer(Some(512));
        explicit_none.set_peer_record_size_limit(None);
        let cleared = explicit_none
            .write_record(content_type::APPLICATION_DATA, &payload)
            .unwrap();
        assert_eq!(
            untouched, cleared,
            "clearing the limit must restore the default framing"
        );

        let frames = record_frames(&untouched);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].1, MAX_RECORD_PAYLOAD + 1 + TAG_LEN);
        assert_eq!(frames[1].1, 100 + 1 + TAG_LEN);
    }

    /// RFC 8449 §4: "Even if a larger record size limit is provided by a peer,
    /// an endpoint MUST NOT send records larger than the protocol-defined
    /// limit."
    #[test]
    fn peer_limit_above_the_protocol_maximum_does_not_grow_records() {
        for limit in [MAX_RECORD_PAYLOAD as u16 + 1, 20000, u16::MAX] {
            let tls13 = tls13_writer(Some(limit));
            assert_eq!(
                tls13.max_plaintext_chunk(content_type::APPLICATION_DATA),
                MAX_RECORD_PAYLOAD,
                "TLS 1.3 limit {limit} must not raise records above 2^14"
            );
            let tls12 = tls12_writer(Some(limit));
            assert_eq!(
                tls12.max_plaintext_chunk(content_type::APPLICATION_DATA),
                MAX_RECORD_PAYLOAD,
                "TLS 1.2 limit {limit} must not raise records above 2^14"
            );
        }

        let mut writer = tls13_writer(Some(u16::MAX));
        let payload = vec![0x11u8; MAX_RECORD_PAYLOAD + 1];
        let frames = record_frames(
            &writer
                .write_record(content_type::APPLICATION_DATA, &payload)
                .unwrap(),
        );
        assert_eq!(
            frames.len(),
            2,
            "an oversized limit must still split at 2^14"
        );
        assert_eq!(frames[0].1, MAX_RECORD_PAYLOAD + 1 + TAG_LEN);
    }

    /// The limit governs application data. Handshake, alert and CCS records are
    /// a fingerprint surface and must stay exactly as they were.
    #[test]
    fn peer_limit_does_not_apply_to_non_application_records() {
        let mut writer = tls13_writer(Some(64));
        for ct in [
            content_type::HANDSHAKE,
            content_type::ALERT,
            content_type::CHANGE_CIPHER_SPEC,
        ] {
            assert_eq!(
                writer.max_plaintext_chunk(ct),
                MAX_RECORD_PAYLOAD,
                "content type 0x{ct:02x} must not be chunked by the peer's limit"
            );
        }

        let hs_payload = vec![0x0Bu8; 500];
        let frames = record_frames(
            &writer
                .write_record(content_type::HANDSHAKE, &hs_payload)
                .unwrap(),
        );
        assert_eq!(
            frames.len(),
            1,
            "a 500-byte handshake message must stay in one record under a 64-octet limit"
        );
        assert_eq!(frames[0].1, 500 + 1 + TAG_LEN);
    }

    /// RFC 8449 §4: "Unprotected messages are not subject to this limit."
    #[test]
    fn peer_limit_does_not_apply_to_unprotected_records() {
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_peer_record_size_limit(Some(64));
        assert_eq!(
            writer.max_plaintext_chunk(content_type::APPLICATION_DATA),
            MAX_RECORD_PAYLOAD,
            "a plaintext record is not protected, so the limit does not apply"
        );

        let frames = record_frames(
            &writer
                .write_record(content_type::APPLICATION_DATA, &[0x22u8; 500])
                .unwrap(),
        );
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, 500);
    }

    /// The parser rejects anything below 64, but the writer must still be
    /// total: a degenerate limit must not panic or stall.
    #[test]
    fn degenerate_peer_limit_still_makes_progress() {
        for limit in [0u16, 1] {
            let mut writer = tls13_writer(Some(limit));
            assert_eq!(
                writer.max_plaintext_chunk(content_type::APPLICATION_DATA),
                1
            );
            let frames = record_frames(
                &writer
                    .write_record(content_type::APPLICATION_DATA, &[0x33u8; 4])
                    .unwrap(),
            );
            assert_eq!(
                frames.len(),
                4,
                "limit {limit} must emit one byte per record"
            );
        }
    }

    #[test]
    fn test_tls13_encrypted_multiple_records_seq_num() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        let r1 = writer.write_record(0x16, b"first").unwrap();
        let r2 = writer.write_record(0x16, b"second").unwrap();

        // Both should decrypt with correct sequence numbers
        let mut reader = RecordReader::new();
        reader.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());

        reader.feed(&r1);
        reader.feed(&r2);

        let p1 = reader.next_record().unwrap().unwrap();
        assert_eq!(p1.payload, b"first");

        let p2 = reader.next_record().unwrap().unwrap();
        assert_eq!(p2.payload, b"second");
    }
}
