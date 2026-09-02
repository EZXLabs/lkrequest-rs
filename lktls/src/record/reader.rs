//! TLS Record reader — reads and decrypts incoming TLS records.
//!
//! The `RecordReader` accumulates bytes from the transport and produces
//! [`PlaintextRecord`]s.  Before keys are established (during the initial
//! handshake), records are returned as-is.  After key installation via
//! [`RecordReader::set_keys`] or [`RecordReader::set_tls12_keys`], all
//! incoming records are automatically decrypted and their sequence numbers
//! are tracked for AEAD nonce construction.

use super::{
    RecordHeader, Tls12RecordCipher, MAX_CIPHERTEXT_EXPANSION, MAX_RECORD_PAYLOAD,
    MAX_TLS13_INNER_PLAINTEXT, RECORD_HEADER_SIZE,
};
use crate::crypto::aead::Aead;
use crate::error::{AlertDescription, Result, TlsError};
use crate::handshake::content_type;

/// A decrypted TLS record.
#[derive(Debug)]
pub struct PlaintextRecord {
    /// The actual content type.
    /// For TLS 1.3 encrypted records, this is extracted from the last byte
    /// of the decrypted payload (inner content type), not the record header.
    /// For TLS 1.2, this is the content type from the record header.
    pub content_type: u8,
    /// The decrypted payload (without inner content type byte for TLS 1.3).
    pub payload: Vec<u8>,
}

/// Reads TLS records from a byte stream, decrypting them once keys are
/// established.
pub struct RecordReader {
    /// Buffer for accumulating incoming bytes.
    buf: Vec<u8>,
    /// Read sequence number (for AEAD nonce construction).
    seq_num: u64,
    /// TLS 1.3 AEAD decryption key + IV (None before keys are established).
    aead: Option<Aead>,
    /// TLS 1.2 record cipher (None if using TLS 1.3 or plaintext).
    tls12_cipher: Option<Tls12RecordCipher>,
    /// The RFC 8449 `record_size_limit` **we** advertised, if any.
    ///
    /// `None` — the case for every profile that does not send the extension,
    /// Chrome included — means only the protocol maximum applies.
    own_record_size_limit: Option<u16>,
}

impl RecordReader {
    /// Create a new record reader (plaintext mode — no decryption).
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(
                MAX_RECORD_PAYLOAD + RECORD_HEADER_SIZE + MAX_CIPHERTEXT_EXPANSION,
            ),
            seq_num: 0,
            aead: None,
            tls12_cipher: None,
            own_record_size_limit: None,
        }
    }

    /// Enforce the RFC 8449 `record_size_limit` **we** advertised.
    ///
    /// The extension is directional (RFC 8449 §4: "The value of RecordSizeLimit
    /// is the maximum size of record in octets that the endpoint is willing to
    /// receive"), so the value in our ClientHello bounds what the peer may send
    /// *us*, and "an endpoint that receives a record larger than its advertised
    /// limit MUST generate a fatal 'record_overflow' alert". This is the receive
    /// mirror of
    /// [`crate::record::writer::RecordWriter::set_peer_record_size_limit`].
    ///
    /// Call it before the handshake starts — the extension travels in the very
    /// first flight, so the limit is in force from the first protected record.
    /// A profile that advertises nothing passes `None` and only the
    /// protocol-defined maximum applies.
    pub fn set_own_record_size_limit(&mut self, limit: Option<u16>) {
        self.own_record_size_limit = limit;
    }

    /// The `record_size_limit` we advertised, if any.
    pub fn own_record_size_limit(&self) -> Option<u16> {
        self.own_record_size_limit
    }

    /// The largest *protected* plaintext this reader accepts in one record.
    ///
    /// Two bounds combine, the smaller winning:
    ///
    /// 1. *Protocol.* RFC 8446 §5.2 caps a TLS 1.3 `TLSInnerPlaintext` at
    ///    [`MAX_TLS13_INNER_PLAINTEXT`]; RFC 5246 §6.2.3 caps a TLS 1.2 fragment
    ///    at [`MAX_RECORD_PAYLOAD`]. A record over that is a `record_overflow`
    ///    whether or not any extension was negotiated.
    /// 2. *RFC 8449.* Our advertised limit, expressed in exactly the same units:
    ///    "the complete length of TLSInnerPlaintext" under TLS 1.3 — content
    ///    plus the inner content-type octet plus padding — and the plain
    ///    fragment under TLS 1.2. (The writer subtracts one for TLS 1.3 because
    ///    it starts from a payload that has yet to gain its type octet; here the
    ///    decrypted buffer already carries it, so no adjustment applies.)
    ///
    /// Unprotected records are deliberately not routed through this: RFC 8449 §4
    /// says "unprotected messages are not subject to this limit", and their 2^14
    /// ceiling is applied to the record header instead.
    fn max_protected_plaintext(&self) -> usize {
        let protocol_max = if self.aead.is_some() {
            MAX_TLS13_INNER_PLAINTEXT
        } else {
            MAX_RECORD_PAYLOAD
        };
        match self.own_record_size_limit {
            Some(limit) => usize::from(limit).min(protocol_max),
            None => protocol_max,
        }
    }

    /// RFC 8449 §4 / RFC 8446 §5.2: reject a decrypted record that is larger
    /// than the limit we advertised, or than the protocol allows at all.
    fn check_protected_plaintext_len(&self, len: usize) -> Result<()> {
        let max = self.max_protected_plaintext();
        if len > max {
            return Err(TlsError::local_alert(
                AlertDescription::RecordOverflow,
                format!("decrypted record is {len} bytes, over the {max}-byte receive limit"),
            ));
        }
        Ok(())
    }

    /// Install TLS 1.3 decryption keys. All subsequent records will be decrypted.
    /// Resets the sequence number to 0.
    pub fn set_keys(&mut self, aead: Aead) {
        self.aead = Some(aead);
        self.tls12_cipher = None;
        self.seq_num = 0;
    }

    /// Install TLS 1.2 decryption keys. All subsequent records will be decrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        self.tls12_cipher = Some(cipher);
        self.aead = None;
        self.seq_num = 0;
    }

    /// Feed raw bytes from the transport into the reader.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the number of buffered bytes not yet consumed.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Try to read the next complete TLS record.
    ///
    /// Returns `Ok(None)` if not enough data is available yet.
    /// Returns `Ok(Some(record))` when a complete record is available.
    pub fn next_record(&mut self) -> Result<Option<PlaintextRecord>> {
        // Step 1: Do we have a complete header?
        if self.buf.len() < RECORD_HEADER_SIZE {
            return Ok(None);
        }

        let header = RecordHeader::from_bytes(self.buf[..RECORD_HEADER_SIZE].try_into().unwrap());

        let payload_len = header.length as usize;
        let is_encrypted = self.aead.is_some() || self.tls12_cipher.is_some();
        // RFC 8446 §5.1 / RFC 5246 §6.2.1: plaintext records are limited to
        // 2^14 bytes; encrypted records may add up to 256 bytes of overhead.
        // Either way the required response is a fatal `record_overflow`
        // (RFC 8446 §5.1, §5.2).
        let max_len = if is_encrypted {
            MAX_RECORD_PAYLOAD + MAX_CIPHERTEXT_EXPANSION
        } else {
            MAX_RECORD_PAYLOAD
        };
        if payload_len > max_len {
            return Err(TlsError::local_alert(
                AlertDescription::RecordOverflow,
                format!("TLS record too large: {payload_len} bytes (max {max_len})"),
            ));
        }

        // Step 2: Do we have the full record?
        let total_len = RECORD_HEADER_SIZE + payload_len;
        if self.buf.len() < total_len {
            return Ok(None);
        }

        // Step 3: Extract the record payload
        let raw_payload = self.buf[RECORD_HEADER_SIZE..total_len].to_vec();
        // Remove the consumed record from the buffer
        self.buf.drain(..total_len);

        // Step 4a: TLS 1.2 decryption — decrypt ALL records after keys installed
        if let Some(ref tls12_cipher) = self.tls12_cipher {
            // In TLS 1.2, after CCS, ALL records are encrypted.
            // The content type in the header is the real content type.
            // AAD = seq_num(8) + content_type(1) + version(2) + plaintext_length(2)

            let plaintext = match tls12_cipher {
                Tls12RecordCipher::Gcm(gcm) => {
                    // GCM: raw_payload = explicit_nonce(8) + ciphertext + tag(16)
                    // Plaintext length = record payload length - 8 - 16
                    if raw_payload.len() < 8 + 16 {
                        return Err(TlsError::CryptoError("TLS 1.2 GCM record too short".into()));
                    }
                    let plaintext_len = raw_payload.len() - 8 - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    gcm.decrypt(&aad, &raw_payload)?
                }
                Tls12RecordCipher::Chacha20(chacha) => {
                    // ChaCha20: raw_payload = ciphertext + tag(16), no explicit nonce
                    if raw_payload.len() < 16 {
                        return Err(TlsError::CryptoError(
                            "TLS 1.2 ChaCha20 record too short".into(),
                        ));
                    }
                    let plaintext_len = raw_payload.len() - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    chacha.decrypt(self.seq_num, &aad, &raw_payload)?
                }
                Tls12RecordCipher::Cbc(cbc) => {
                    // CBC: raw_payload = iv(16) + encrypted(plaintext + mac + padding)
                    // AAD uses record payload length (which includes IV + encrypted data).
                    // The CBC cipher internally rebuilds the correct AAD with plaintext length.
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    // For CBC, pass the record payload length in AAD; the cipher
                    // will reconstruct the correct plaintext length internally.
                    let rpl = raw_payload.len() as u16;
                    aad[11] = (rpl >> 8) as u8;
                    aad[12] = rpl as u8;

                    cbc.decrypt(&aad, &raw_payload)?
                }
            };
            self.seq_num = self.seq_num.checked_add(1).ok_or_else(|| {
                TlsError::UnexpectedMessage("record sequence number overflow".to_string())
            })?;

            // RFC 8449 §4 / RFC 5246 §6.2.3: the fragment we just recovered must
            // fit the limit we advertised, and the protocol's 2^14 in any case.
            self.check_protected_plaintext_len(plaintext.len())?;
            check_content_type(header.content_type)?;

            return Ok(Some(PlaintextRecord {
                content_type: header.content_type,
                payload: plaintext,
            }));
        }

        // Step 4b: TLS 1.3 decryption — only APPLICATION_DATA records
        if let Some(ref aead) = self.aead {
            if header.content_type == content_type::APPLICATION_DATA {
                // TLS 1.3: encrypted records use content_type APPLICATION_DATA on the wire.
                // AAD = the 5-byte record header (with the encrypted length).
                let aad = header.to_bytes();
                let plaintext = aead.decrypt(self.seq_num, &aad, &raw_payload)?;
                self.seq_num = self.seq_num.checked_add(1).ok_or_else(|| {
                    TlsError::UnexpectedMessage("record sequence number overflow".to_string())
                })?;

                // RFC 8449 §4: our advertised limit counts the whole
                // TLSInnerPlaintext, so it is checked before the content-type
                // octet and padding are stripped. RFC 8446 §5.2's 2^14+1 ceiling
                // rides along in the same comparison.
                self.check_protected_plaintext_len(plaintext.len())?;

                // TLS 1.3: the last non-zero byte of the decrypted payload is the
                // inner content type. Strip trailing zeros and the content type byte.
                let (inner_ct, inner_payload) = strip_inner_content_type(&plaintext)?;
                check_content_type(inner_ct)?;

                return Ok(Some(PlaintextRecord {
                    content_type: inner_ct,
                    payload: inner_payload,
                }));
            }
        }

        // Unprotected record.
        //
        // RFC 8446 §5.2: once keys are installed every handshake, alert and
        // application-data record travels encrypted, so anything still in the
        // clear here is injected — a forged plaintext fatal alert would
        // otherwise tear down the connection for free. The single exception is
        // ChangeCipherSpec, which §D.4's middlebox-compatibility mode sends
        // unencrypted ("an implementation may receive an unencrypted record of
        // type change_cipher_spec") and the handshake driver ignores.
        if is_encrypted && header.content_type != content_type::CHANGE_CIPHER_SPEC {
            return Err(TlsError::local_alert(
                AlertDescription::UnexpectedMessage,
                format!(
                    "plaintext record (content_type=0x{:02x}) received after keys were installed",
                    header.content_type
                ),
            ));
        }

        check_content_type(header.content_type)?;

        Ok(Some(PlaintextRecord {
            content_type: header.content_type,
            payload: raw_payload,
        }))
    }
}

impl Default for RecordReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject a record whose content type is not one this protocol defines.
///
/// RFC 8446 §5.1: "If a TLS implementation receives an unexpected record type,
/// it MUST terminate the connection with an 'unexpected_message' alert."
/// Silently skipping the record instead lets a peer smuggle content past every
/// layer above the record reader — the four types below are the whole of what we
/// negotiate (no heartbeat, no application-defined types).
fn check_content_type(content_type: u8) -> Result<()> {
    match content_type {
        content_type::CHANGE_CIPHER_SPEC
        | content_type::ALERT
        | content_type::HANDSHAKE
        | content_type::APPLICATION_DATA => Ok(()),
        other => Err(TlsError::local_alert(
            AlertDescription::UnexpectedMessage,
            format!("unknown TLS record content type 0x{other:02x}"),
        )),
    }
}

/// Strip the TLS 1.3 inner content type from a decrypted record payload.
///
/// The inner content type is the last non-zero byte. Everything after (zeros)
/// is padding and is stripped.
fn strip_inner_content_type(plaintext: &[u8]) -> Result<(u8, Vec<u8>)> {
    // Find the last non-zero byte (the inner content type)
    let ct_pos = plaintext.iter().rposition(|&b| b != 0).ok_or_else(|| {
        TlsError::UnexpectedMessage("Decrypted record has no content type".to_string())
    })?;

    let inner_content_type = plaintext[ct_pos];
    let inner_payload = plaintext[..ct_pos].to_vec();

    Ok((inner_content_type, inner_payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadAlgorithm;
    use crate::crypto::tls12_cipher::Tls12GcmCipher;

    #[test]
    fn test_read_plaintext_record() {
        let mut reader = RecordReader::new();

        // Build a handshake record: type=0x16, version=0x0303, length=5
        let payload = b"hello";
        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        record.extend_from_slice(payload);

        reader.feed(&record);
        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16);
        assert_eq!(result.payload, b"hello");
    }

    #[test]
    fn test_partial_feed() {
        let mut reader = RecordReader::new();

        // Feed only the header first
        reader.feed(&[0x16, 0x03, 0x03, 0x00, 0x03]);
        assert!(reader.next_record().unwrap().is_none());

        // Feed the payload
        reader.feed(&[0x01, 0x02, 0x03]);
        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_multiple_records() {
        let mut reader = RecordReader::new();

        // Two records back to back
        let mut data = Vec::new();
        data.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB]);
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xCC]);
        reader.feed(&data);

        let r1 = reader.next_record().unwrap().unwrap();
        assert_eq!(r1.content_type, 0x16);
        assert_eq!(r1.payload, vec![0xAA, 0xBB]);

        let r2 = reader.next_record().unwrap().unwrap();
        assert_eq!(r2.content_type, 0x17);
        assert_eq!(r2.payload, vec![0xCC]);

        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn test_tls13_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        // Build inner plaintext: payload + inner content type
        let inner_payload = b"handshake data";
        let mut plaintext_with_ct = inner_payload.to_vec();
        plaintext_with_ct.push(0x16); // inner content type = handshake

        // Compute the expected ciphertext length to build the header (AAD) first
        let ct_len = plaintext_with_ct.len() + 16; // payload + AEAD tag
        let header_bytes: [u8; 5] = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];

        // Encrypt with the header as AAD
        let enc = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();
        let ct = enc.encrypt(0, &header_bytes, &plaintext_with_ct).unwrap();
        assert_eq!(ct.len(), ct_len);

        // Assemble the full TLS record
        let mut record = header_bytes.to_vec();
        record.extend_from_slice(&ct);

        // Decrypt via RecordReader
        let mut reader = RecordReader::new();
        reader.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16); // inner content type
        assert_eq!(result.payload, inner_payload);
    }

    #[test]
    fn test_tls12_gcm_encrypted_record_roundtrip() {
        let key = [0x42u8; 16];
        let implicit_iv = [0x01, 0x02, 0x03, 0x04];

        // Use the writer to create a TLS 1.2 encrypted record
        use crate::record::writer::RecordWriter;
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let plaintext = b"TLS 1.2 GCM reader test";
        let record = writer.write_record(0x16, plaintext).unwrap();

        // Decrypt with reader
        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        reader.feed(&record);

        let result = reader.next_record().unwrap().unwrap();
        assert_eq!(result.content_type, 0x16);
        assert_eq!(result.payload, plaintext);
    }

    #[test]
    fn test_tls12_gcm_multiple_records() {
        let key = [0x42u8; 16];
        let implicit_iv = [0xAA, 0xBB, 0xCC, 0xDD];

        use crate::record::writer::RecordWriter;
        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        let r1 = writer.write_record(0x16, b"first").unwrap();
        let r2 = writer.write_record(0x17, b"second").unwrap();

        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));

        reader.feed(&r1);
        reader.feed(&r2);

        let p1 = reader.next_record().unwrap().unwrap();
        assert_eq!(p1.content_type, 0x16);
        assert_eq!(p1.payload, b"first");

        let p2 = reader.next_record().unwrap().unwrap();
        assert_eq!(p2.content_type, 0x17);
        assert_eq!(p2.payload, b"second");
    }

    #[test]
    fn test_strip_inner_content_type() {
        // Normal case: payload + content_type byte
        let data = vec![0x01, 0x02, 0x03, 0x16];
        let (ct, payload) = strip_inner_content_type(&data).unwrap();
        assert_eq!(ct, 0x16);
        assert_eq!(payload, vec![0x01, 0x02, 0x03]);

        // With trailing zero padding
        let data_padded = vec![0x01, 0x02, 0x16, 0x00, 0x00];
        let (ct, payload) = strip_inner_content_type(&data_padded).unwrap();
        assert_eq!(ct, 0x16);
        assert_eq!(payload, vec![0x01, 0x02]);
    }

    #[test]
    fn test_record_too_large() {
        let mut reader = RecordReader::new();
        // Record claiming to be 20000 bytes (> MAX_RECORD_PAYLOAD + 256)
        reader.feed(&[0x16, 0x03, 0x03, 0x4E, 0x20]);
        let result = reader.next_record();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Helpers for the record-layer conformance tests below
    // -----------------------------------------------------------------------

    const TEST_KEY: [u8; 16] = [0x42; 16];
    const TEST_IV: [u8; 12] = [0x01; 12];

    /// A reader with TLS 1.3 read keys installed.
    fn tls13_reader() -> RecordReader {
        let mut reader = RecordReader::new();
        reader.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &TEST_KEY, &TEST_IV).unwrap());
        reader
    }

    /// A TLS 1.3 record protecting `inner`, which is a complete
    /// `TLSInnerPlaintext` (content ‖ inner content type ‖ padding).
    fn tls13_record(inner: &[u8]) -> Vec<u8> {
        let ct_len = inner.len() + 16; // AEAD tag
        let header: [u8; 5] = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &TEST_KEY, &TEST_IV).unwrap();
        let mut record = header.to_vec();
        record.extend_from_slice(&aead.encrypt(0, &header, inner).unwrap());
        record
    }

    /// A plaintext record with an arbitrary content type and payload.
    fn plaintext_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = vec![content_type, 0x03, 0x03];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn alert_of(result: Result<Option<PlaintextRecord>>) -> Option<AlertDescription> {
        result
            .err()
            .and_then(|e| e.as_alert().map(|a| a.description))
    }

    // -----------------------------------------------------------------------
    // B-09 — RFC 8446 §5.2: nothing arrives in the clear once keys are installed
    // -----------------------------------------------------------------------

    /// The attack this closes: a fatal alert injected in the clear tears the
    /// connection down without ever proving knowledge of the keys.
    #[test]
    fn injected_plaintext_alert_after_keys_is_rejected() {
        let mut reader = tls13_reader();
        // alert(21), fatal(2), handshake_failure(40)
        reader.feed(&plaintext_record(content_type::ALERT, &[0x02, 0x28]));

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage),
            "a plaintext alert after key installation must be rejected, not delivered"
        );
    }

    #[test]
    fn plaintext_handshake_after_keys_is_rejected() {
        let mut reader = tls13_reader();
        reader.feed(&plaintext_record(content_type::HANDSHAKE, &[0x04, 0, 0, 0]));

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage),
            "a plaintext handshake message after key installation must be rejected"
        );
    }

    /// The one legitimate exception: TLS 1.3 middlebox-compatibility mode
    /// (RFC 8446 §D.4) sends ChangeCipherSpec unencrypted, and the handshake
    /// driver relies on still receiving it after the handshake keys are in.
    #[test]
    fn plaintext_change_cipher_spec_after_keys_is_still_accepted() {
        let mut reader = tls13_reader();
        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[0x01]));

        let record = reader
            .next_record()
            .expect("middlebox-compat CCS must survive key installation")
            .expect("a complete CCS record was fed");
        assert_eq!(record.content_type, content_type::CHANGE_CIPHER_SPEC);
        assert_eq!(record.payload, vec![0x01]);
    }

    /// Interleaving still works: a CCS in the clear followed by a real protected
    /// record does not desynchronise the sequence number.
    #[test]
    fn plaintext_ccs_does_not_disturb_the_following_protected_record() {
        let mut reader = tls13_reader();
        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[0x01]));
        let mut inner = b"handshake data".to_vec();
        inner.push(content_type::HANDSHAKE);
        reader.feed(&tls13_record(&inner));

        let ccs = reader.next_record().unwrap().unwrap();
        assert_eq!(ccs.content_type, content_type::CHANGE_CIPHER_SPEC);

        let protected = reader.next_record().unwrap().unwrap();
        assert_eq!(protected.content_type, content_type::HANDSHAKE);
        assert_eq!(protected.payload, b"handshake data");
    }

    // -----------------------------------------------------------------------
    // B-10 — RFC 8446 §5.1: an unknown content type aborts the connection
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_plaintext_content_type_is_unexpected_message() {
        for content_type in [0x00u8, 0x18, 0x19, 0xff] {
            let mut reader = RecordReader::new();
            reader.feed(&plaintext_record(content_type, b"payload"));

            assert_eq!(
                alert_of(reader.next_record()),
                Some(AlertDescription::UnexpectedMessage),
                "content type 0x{content_type:02x} must abort, not be skipped"
            );
        }
    }

    #[test]
    fn unknown_inner_content_type_is_unexpected_message() {
        // 0x18 is heartbeat — never negotiated, so it must not reach the layers
        // above under cover of a well-formed encrypted record.
        let mut inner = b"smuggled".to_vec();
        inner.push(0x18);

        let mut reader = tls13_reader();
        reader.feed(&tls13_record(&inner));

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage),
            "an unknown TLS 1.3 inner content type must abort the connection"
        );
    }

    // -----------------------------------------------------------------------
    // N-01 — RFC 8449 §4: enforce the `record_size_limit` we advertised
    // -----------------------------------------------------------------------

    #[test]
    fn no_advertised_limit_by_default() {
        assert_eq!(
            RecordReader::new().own_record_size_limit(),
            None,
            "a profile that sends no extension must leave the reader unbounded"
        );
    }

    /// The limit counts the whole `TLSInnerPlaintext`, so 63 content bytes plus
    /// the content-type octet is exactly a 64-byte record: the largest allowed.
    #[test]
    fn tls13_record_exactly_at_our_advertised_limit_is_accepted() {
        let mut inner = vec![0xAB; 63];
        inner.push(content_type::APPLICATION_DATA);

        let mut reader = tls13_reader();
        reader.set_own_record_size_limit(Some(64));
        reader.feed(&tls13_record(&inner));

        let record = reader
            .next_record()
            .expect("a record exactly at the limit must be accepted")
            .expect("a complete record was fed");
        assert_eq!(record.payload.len(), 63);
    }

    /// One octet more — 64 content bytes plus the type octet — is over the
    /// advertised 64 and MUST be a fatal `record_overflow`.
    #[test]
    fn tls13_record_over_our_advertised_limit_is_record_overflow() {
        let mut inner = vec![0xAB; 64];
        inner.push(content_type::APPLICATION_DATA);

        let mut reader = tls13_reader();
        reader.set_own_record_size_limit(Some(64));
        reader.feed(&tls13_record(&inner));

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::RecordOverflow),
            "a protected record over our advertised limit must be record_overflow"
        );
    }

    /// Padding counts too — RFC 8449 §4 measures "the complete length of
    /// TLSInnerPlaintext", so a small payload padded past the limit still fails.
    #[test]
    fn tls13_padding_counts_towards_our_advertised_limit() {
        let mut inner = vec![0xAB; 8];
        inner.push(content_type::APPLICATION_DATA);
        inner.extend_from_slice(&[0u8; 100]); // padding

        let mut reader = tls13_reader();
        reader.set_own_record_size_limit(Some(64));
        reader.feed(&tls13_record(&inner));

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::RecordOverflow),
            "TLS 1.3 padding is part of the measured TLSInnerPlaintext"
        );
    }

    /// Even with no extension advertised, RFC 8446 §5.2 caps the decrypted
    /// `TLSInnerPlaintext` at 2^14+1 — a ciphertext small enough to clear the
    /// header check can still decrypt to something over that.
    #[test]
    fn tls13_inner_plaintext_over_the_protocol_maximum_is_record_overflow() {
        let mut inner = vec![0xAB; MAX_TLS13_INNER_PLAINTEXT];
        inner.push(content_type::APPLICATION_DATA);
        let record = tls13_record(&inner);
        assert!(
            record.len() - RECORD_HEADER_SIZE <= MAX_RECORD_PAYLOAD + MAX_CIPHERTEXT_EXPANSION,
            "the ciphertext must be small enough to pass the record-header check"
        );

        let mut reader = tls13_reader();
        reader.feed(&record);

        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::RecordOverflow),
            "a decrypted TLSInnerPlaintext over 2^14+1 must be record_overflow"
        );
    }

    /// TLS 1.2 measures the fragment itself — no content-type octet — so 64
    /// bytes is the largest a 64-byte limit allows, and 65 overflows.
    #[test]
    fn tls12_record_limit_is_measured_on_the_fragment() {
        use crate::record::writer::RecordWriter;

        let key = [0x42u8; 16];
        let implicit_iv = [0x01, 0x02, 0x03, 0x04];

        let mut writer = RecordWriter::new();
        writer.mark_post_initial();
        writer.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        let at_limit = writer
            .write_record(content_type::APPLICATION_DATA, &[0xCD; 64])
            .unwrap();
        let over_limit = writer
            .write_record(content_type::APPLICATION_DATA, &[0xCD; 65])
            .unwrap();

        let mut reader = RecordReader::new();
        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&key, &implicit_iv, false).unwrap(),
        ));
        reader.set_own_record_size_limit(Some(64));

        reader.feed(&at_limit);
        let accepted = reader
            .next_record()
            .expect("a 64-byte fragment is exactly at a 64-byte limit")
            .expect("a complete record was fed");
        assert_eq!(accepted.payload.len(), 64);

        reader.feed(&over_limit);
        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::RecordOverflow),
            "a 65-byte TLS 1.2 fragment must overflow a 64-byte limit"
        );
    }

    /// The limit applies only to protected records: RFC 8449 §4, "unprotected
    /// messages are not subject to this limit".
    #[test]
    fn advertised_limit_does_not_apply_before_keys_are_installed() {
        let mut reader = RecordReader::new();
        reader.set_own_record_size_limit(Some(64));
        reader.feed(&plaintext_record(content_type::HANDSHAKE, &[0xAB; 512]));

        let record = reader
            .next_record()
            .expect("an unprotected record is not subject to the limit")
            .expect("a complete record was fed");
        assert_eq!(record.payload.len(), 512);
    }

    /// A limit larger than the protocol allows cannot raise our ceiling —
    /// "an endpoint MUST NOT send records larger than the protocol-defined
    /// limit" has a receive-side twin.
    #[test]
    fn advertised_limit_cannot_exceed_the_protocol_maximum() {
        let mut reader = tls13_reader();
        reader.set_own_record_size_limit(Some(u16::MAX));
        assert_eq!(reader.max_protected_plaintext(), MAX_TLS13_INNER_PLAINTEXT);

        reader.set_tls12_keys(Tls12RecordCipher::Gcm(
            Tls12GcmCipher::new(&[0x42u8; 16], &[0x01, 0x02, 0x03, 0x04], false).unwrap(),
        ));
        assert_eq!(reader.max_protected_plaintext(), MAX_RECORD_PAYLOAD);
    }
}
