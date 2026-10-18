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
    MAX_TLS12_CIPHERTEXT_EXPANSION, MAX_TLS13_INNER_PLAINTEXT, RECORD_HEADER_SIZE,
};
use crate::crypto::aead::Aead;
use crate::error::{AlertDescription, Result, TlsError};
use crate::handshake::content_type;
use crate::profile::types::TlsClientHelloStyle;

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
    /// Browser-specific alert mapping for invalid TLS 1.3 CCS records.
    client_style: TlsClientHelloStyle,
    tls13_selected: bool,
    tls13_handshake_complete: bool,
    consecutive_empty_records: u8,
    nss_ccs_received_with_keys: bool,
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
            client_style: TlsClientHelloStyle::Generic,
            tls13_selected: false,
            tls13_handshake_complete: false,
            consecutive_empty_records: 0,
            nss_ccs_received_with_keys: false,
        }
    }

    pub(crate) fn set_client_style(&mut self, style: TlsClientHelloStyle) {
        self.client_style = style;
    }

    pub(crate) fn select_tls13(&mut self) {
        self.tls13_selected = true;
    }

    pub(crate) fn finish_tls13_handshake(&mut self) {
        self.tls13_handshake_complete = true;
    }

    fn count_empty_record(&mut self, empty: bool) -> Result<()> {
        if self.tls13_selected && self.client_style == TlsClientHelloStyle::ChromiumBoringssl {
            if empty {
                self.consecutive_empty_records = self.consecutive_empty_records.saturating_add(1);
                if self.consecutive_empty_records > 32 {
                    return Err(TlsError::local_alert(
                        AlertDescription::UnexpectedMessage,
                        "too many consecutive empty TLS records or compatibility CCS records",
                    ));
                }
            } else {
                self.consecutive_empty_records = 0;
            }
        }
        Ok(())
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
        self.select_tls13();
    }

    /// Install TLS 1.2 decryption keys. All subsequent records will be decrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        self.tls12_cipher = Some(cipher);
        self.aead = None;
        self.seq_num = 0;
        self.tls13_selected = false;
        self.tls13_handshake_complete = false;
        self.consecutive_empty_records = 0;
        self.nss_ccs_received_with_keys = false;
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
        if is_encrypted
            && self.client_style == TlsClientHelloStyle::ChromiumBoringssl
            && header.version != 0x0303
        {
            return Err(TlsError::local_alert(
                AlertDescription::ProtocolVersion,
                "record version differs from the selected TLS record version",
            ));
        }
        // RFC 8446 §5.1 / RFC 5246 §6.2.1: plaintext records are limited to
        // 2^14 bytes; TLS 1.3 ciphertext may add 256 bytes, TLS 1.2 2048 bytes.
        // Either way the required response is a fatal `record_overflow`
        // (RFC 8446 §5.1, §5.2).
        let max_len = if self.tls12_cipher.is_some() {
            MAX_RECORD_PAYLOAD + MAX_TLS12_CIPHERTEXT_EXPANSION
        } else if is_encrypted {
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

            let authentication_failure = || {
                TlsError::local_alert(
                    AlertDescription::BadRecordMac,
                    "TLS 1.2 record authentication failed",
                )
            };

            let plaintext = match tls12_cipher {
                Tls12RecordCipher::Gcm(gcm) => {
                    // GCM: raw_payload = explicit_nonce(8) + ciphertext + tag(16)
                    // Plaintext length = record payload length - 8 - 16
                    if raw_payload.len() < 8 + 16 {
                        return Err(authentication_failure());
                    }
                    let plaintext_len = raw_payload.len() - 8 - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    gcm.decrypt(&aad, &raw_payload)
                        .map_err(|_| authentication_failure())?
                }
                Tls12RecordCipher::Chacha20(chacha) => {
                    // ChaCha20: raw_payload = ciphertext + tag(16), no explicit nonce
                    if raw_payload.len() < 16 {
                        return Err(authentication_failure());
                    }
                    let plaintext_len = raw_payload.len() - 16;
                    let mut aad = [0u8; 13];
                    aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
                    aad[8] = header.content_type;
                    aad[9] = (header.version >> 8) as u8;
                    aad[10] = header.version as u8;
                    aad[11] = (plaintext_len >> 8) as u8;
                    aad[12] = plaintext_len as u8;

                    chacha
                        .decrypt(self.seq_num, &aad, &raw_payload)
                        .map_err(|_| authentication_failure())?
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

                    cbc.decrypt(&aad, &raw_payload)
                        .map_err(|_| authentication_failure())?
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
                // NSS rejects impossible ciphertext sizes and mismatched versions
                // before authentication, while BoringSSL checks the version above.
                if self.client_style == TlsClientHelloStyle::FirefoxNss {
                    let maximum = self.max_protected_plaintext() + aead.algorithm().tag_len();
                    if raw_payload.len() > maximum {
                        return Err(TlsError::local_alert(
                            AlertDescription::RecordOverflow,
                            "TLS 1.3 ciphertext exceeds the cipher-specific receive limit",
                        ));
                    }
                    if header.version != 0x0303 {
                        return Err(TlsError::local_alert(
                            AlertDescription::BadRecordMac,
                            "TLS 1.3 record version differs from the selected record version",
                        ));
                    }
                }
                // TLS 1.3: encrypted records use content_type APPLICATION_DATA on the wire.
                // AAD = the 5-byte record header (with the encrypted length).
                let aad = header.to_bytes();
                let plaintext = aead
                    .decrypt(self.seq_num, &aad, &raw_payload)
                    .map_err(|_| {
                        TlsError::local_alert(
                            AlertDescription::BadRecordMac,
                            "TLS 1.3 record authentication failed",
                        )
                    })?;
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
                let (inner_ct, inner_payload) =
                    strip_inner_content_type(&plaintext).map_err(|_| {
                        TlsError::local_alert(
                            if self.client_style == TlsClientHelloStyle::ChromiumBoringssl {
                                AlertDescription::DecryptError
                            } else {
                                AlertDescription::UnexpectedMessage
                            },
                            "decrypted TLS 1.3 record has no inner content type",
                        )
                    })?;
                check_content_type(inner_ct)?;
                if inner_ct == content_type::CHANGE_CIPHER_SPEC {
                    // Protected CCS is never the TLS 1.3 compatibility message.
                    // NSS validates its body before rejecting the record type.
                    let description = if self.client_style == TlsClientHelloStyle::FirefoxNss {
                        if inner_payload.len() != 1 {
                            AlertDescription::DecodeError
                        } else if inner_payload != [1] {
                            AlertDescription::IllegalParameter
                        } else {
                            AlertDescription::UnexpectedMessage
                        }
                    } else {
                        AlertDescription::UnexpectedMessage
                    };
                    return Err(TlsError::local_alert(
                        description,
                        "protected TLS 1.3 ChangeCipherSpec",
                    ));
                }
                self.count_empty_record(inner_payload.is_empty())?;

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

        if self.aead.is_some()
            && header.content_type == content_type::CHANGE_CIPHER_SPEC
            && (raw_payload != [1] || self.tls13_handshake_complete)
        {
            return Err(TlsError::local_alert(
                if self.client_style == TlsClientHelloStyle::ChromiumBoringssl {
                    AlertDescription::BadRecordMac
                } else {
                    AlertDescription::UnexpectedMessage
                },
                "unexpected plaintext ChangeCipherSpec in the current TLS 1.3 epoch",
            ));
        }

        check_content_type(header.content_type)?;

        if self.tls13_selected
            && header.content_type == content_type::CHANGE_CIPHER_SPEC
            && raw_payload == [1]
        {
            // BoringSSL counts compatibility CCS with empty records. NSS only
            // permits one CCS once handshake read keys have been installed.
            self.count_empty_record(true)?;
            if self.client_style == TlsClientHelloStyle::FirefoxNss && self.aead.is_some() {
                if self.nss_ccs_received_with_keys {
                    return Err(TlsError::local_alert(
                        AlertDescription::UnexpectedMessage,
                        "repeated compatibility ChangeCipherSpec after TLS 1.3 key installation",
                    ));
                }
                self.nss_ccs_received_with_keys = true;
            }
        } else {
            self.count_empty_record(raw_payload.is_empty())?;
        }

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
        tls13_record_at_sequence(inner, 0)
    }

    fn tls13_record_at_sequence(inner: &[u8], sequence: u64) -> Vec<u8> {
        tls13_record_at_version(inner, sequence, 0x0303)
    }

    fn tls13_record_at_version(inner: &[u8], sequence: u64, version: u16) -> Vec<u8> {
        let ct_len = inner.len() + 16; // AEAD tag
        let header: [u8; 5] = [
            0x17,
            (version >> 8) as u8,
            version as u8,
            (ct_len >> 8) as u8,
            ct_len as u8,
        ];
        let aead = Aead::new(AeadAlgorithm::Aes128Gcm, &TEST_KEY, &TEST_IV).unwrap();
        let mut record = header.to_vec();
        record.extend_from_slice(&aead.encrypt(sequence, &header, inner).unwrap());
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

    #[test]
    fn protected_ccs_is_not_a_compatibility_message() {
        let mut reader = tls13_reader();
        reader.feed(&tls13_record(&[1, content_type::CHANGE_CIPHER_SPEC]));
        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage)
        );
    }

    #[test]
    fn malformed_plaintext_ccs_after_keys_is_rejected() {
        for payload in [&[][..], &[2][..], &[1, 1][..]] {
            let mut reader = tls13_reader();
            reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, payload));
            assert_eq!(
                alert_of(reader.next_record()),
                Some(AlertDescription::UnexpectedMessage)
            );
        }
    }

    #[test]
    fn chromium_ccs_budget_resets_only_on_nonempty_records() {
        for encrypted in [false, true] {
            let mut reader = if encrypted {
                tls13_reader()
            } else {
                RecordReader::new()
            };
            reader.set_client_style(TlsClientHelloStyle::ChromiumBoringssl);
            reader.select_tls13();
            for _ in 0..32 {
                reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
                assert!(reader.next_record().unwrap().is_some());
            }
            let record = if encrypted {
                tls13_record(&[8, 0, 0, 2, 0, 0, content_type::HANDSHAKE])
            } else {
                plaintext_record(content_type::HANDSHAKE, &[2, 0, 0, 0])
            };
            reader.feed(&record);
            assert!(!reader.next_record().unwrap().unwrap().payload.is_empty());
            for _ in 0..32 {
                reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
                assert!(reader.next_record().unwrap().is_some());
            }
            reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
            assert_eq!(
                alert_of(reader.next_record()),
                Some(AlertDescription::UnexpectedMessage)
            );
        }
    }

    #[test]
    fn chromium_empty_records_share_the_compatibility_ccs_budget() {
        let mut reader = tls13_reader();
        reader.set_client_style(TlsClientHelloStyle::ChromiumBoringssl);
        for _ in 0..31 {
            reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
            assert!(reader.next_record().unwrap().is_some());
        }
        reader.feed(&tls13_record(&[content_type::HANDSHAKE]));
        assert!(reader.next_record().unwrap().unwrap().payload.is_empty());
        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage)
        );
    }

    #[test]
    fn nss_ccs_budget_starts_with_keys_and_survives_nonempty_records() {
        let mut reader = RecordReader::new();
        reader.set_client_style(TlsClientHelloStyle::FirefoxNss);
        reader.select_tls13();
        for _ in 0..33 {
            reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
            assert!(reader.next_record().unwrap().is_some());
        }
        reader.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &TEST_KEY, &TEST_IV).unwrap());
        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
        assert!(reader.next_record().unwrap().is_some());
        reader.feed(&tls13_record(&[8, 0, 0, 2, 0, 0, content_type::HANDSHAKE]));
        assert!(!reader.next_record().unwrap().unwrap().payload.is_empty());
        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage)
        );
    }

    #[test]
    fn finished_closes_ccs_compatibility_even_after_key_updates() {
        for style in [
            TlsClientHelloStyle::Generic,
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            for previous_ccs in [false, true] {
                for key_update in [false, true] {
                    let mut reader = tls13_reader();
                    reader.set_client_style(style);
                    if previous_ccs {
                        reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
                        assert!(reader.next_record().unwrap().is_some());
                    }
                    reader.finish_tls13_handshake();
                    if key_update {
                        reader.set_keys(
                            Aead::new(AeadAlgorithm::Aes128Gcm, &TEST_KEY, &TEST_IV).unwrap(),
                        );
                    }
                    reader.feed(&plaintext_record(content_type::CHANGE_CIPHER_SPEC, &[1]));
                    let expected = if style == TlsClientHelloStyle::ChromiumBoringssl {
                        AlertDescription::BadRecordMac
                    } else {
                        AlertDescription::UnexpectedMessage
                    };
                    assert_eq!(alert_of(reader.next_record()), Some(expected));
                }
            }
        }
    }

    #[test]
    fn finished_keeps_the_chromium_empty_application_record_budget() {
        let mut reader = tls13_reader();
        reader.set_client_style(TlsClientHelloStyle::ChromiumBoringssl);
        reader.finish_tls13_handshake();
        for sequence in 0..32 {
            reader.feed(&tls13_record_at_sequence(
                &[content_type::APPLICATION_DATA],
                sequence,
            ));
            assert!(reader.next_record().unwrap().unwrap().payload.is_empty());
        }
        reader.feed(&tls13_record_at_sequence(
            &[content_type::APPLICATION_DATA],
            32,
        ));
        assert_eq!(
            alert_of(reader.next_record()),
            Some(AlertDescription::UnexpectedMessage)
        );
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

    #[test]
    fn record_failure_authentication_uses_bad_record_mac_for_each_tls13_cipher() {
        for algorithm in [
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::Chacha20Poly1305,
        ] {
            let key = vec![0x42; algorithm.key_len()];
            let cipher = Aead::new(algorithm, &key, &TEST_IV).unwrap();
            for case in ["valid", "bad_tag", "short_tag", "wrong_nonce"] {
                let mut record = if case == "short_tag" {
                    plaintext_record(content_type::APPLICATION_DATA, &[0; 15])
                } else {
                    let header = [23, 3, 3, 0, 18];
                    let mut record = header.to_vec();
                    record.extend_from_slice(
                        &cipher
                            .encrypt(u64::from(case == "wrong_nonce"), &header, &[0x42, 23])
                            .unwrap(),
                    );
                    record
                };
                if case == "bad_tag" {
                    *record.last_mut().unwrap() ^= 1;
                }
                let mut reader = RecordReader::new();
                reader.set_keys(Aead::new(algorithm, &key, &TEST_IV).unwrap());
                reader.feed(&record);
                if case == "valid" {
                    let plain = reader.next_record().unwrap().unwrap();
                    assert_eq!(plain.content_type, content_type::APPLICATION_DATA);
                    assert_eq!(plain.payload, [0x42]);
                } else {
                    assert_eq!(
                        alert_of(reader.next_record()),
                        Some(AlertDescription::BadRecordMac)
                    );
                }
            }
        }
    }

    #[test]
    fn record_failure_missing_type_matches_browser_alerts() {
        for style in [
            TlsClientHelloStyle::Generic,
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            for inner in [&[][..], &[0][..], &[0; 20][..]] {
                let mut reader = tls13_reader();
                reader.set_client_style(style);
                reader.feed(&tls13_record(inner));
                let expected = if style == TlsClientHelloStyle::ChromiumBoringssl {
                    AlertDescription::DecryptError
                } else {
                    AlertDescription::UnexpectedMessage
                };
                assert_eq!(alert_of(reader.next_record()), Some(expected));
            }
        }
    }

    #[test]
    fn record_failure_authentication_precedes_inner_plaintext_validation() {
        for style in [
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            let mut reader = tls13_reader();
            reader.set_client_style(style);
            let mut record = tls13_record(&[0; 20]);
            *record.last_mut().unwrap() ^= 1;
            reader.feed(&record);
            assert_eq!(
                alert_of(reader.next_record()),
                Some(AlertDescription::BadRecordMac)
            );
        }
    }

    fn tls12_test_cipher(kind: usize) -> Tls12RecordCipher {
        use crate::crypto::tls12_cipher::{CbcMacAlgorithm, Tls12CbcCipher, Tls12Chacha20Cipher};
        match kind {
            0 => Tls12RecordCipher::Gcm(Tls12GcmCipher::new(&[0x42; 16], &[1; 4], false).unwrap()),
            1 => Tls12RecordCipher::Gcm(Tls12GcmCipher::new(&[0x42; 32], &[1; 4], true).unwrap()),
            2 => Tls12RecordCipher::Chacha20(
                Tls12Chacha20Cipher::new(&[0x42; 32], &[1; 12]).unwrap(),
            ),
            3 => Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                &[0x42; 16],
                &[0x24; 20],
                CbcMacAlgorithm::HmacSha1,
            )),
            4 => Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                &[0x42; 16],
                &[0x24; 32],
                CbcMacAlgorithm::HmacSha256,
            )),
            5 => Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                &[0x42; 32],
                &[0x24; 48],
                CbcMacAlgorithm::HmacSha384,
            )),
            _ => unreachable!(),
        }
    }

    #[test]
    fn tls12_record_authentication_failures_are_fatal_bad_record_mac() {
        use crate::record::writer::RecordWriter;
        for kind in 0..6 {
            for scenario in ["normal", "corrupt_tail", "short_record"] {
                let mut writer = RecordWriter::new();
                writer.mark_post_initial();
                writer.set_tls12_keys(tls12_test_cipher(kind));
                let mut record = writer
                    .write_record(content_type::APPLICATION_DATA, b"record-data")
                    .unwrap();
                if scenario == "corrupt_tail" {
                    *record.last_mut().unwrap() ^= 1;
                }
                if scenario == "short_record" {
                    let short = if kind <= 1 {
                        23
                    } else if kind == 2 {
                        15
                    } else {
                        31
                    };
                    record.truncate(5);
                    record[3..5].copy_from_slice(&(short as u16).to_be_bytes());
                    record.resize(5 + short, 0);
                }
                let mut reader = RecordReader::new();
                reader.set_tls12_keys(tls12_test_cipher(kind));
                reader.feed(&record);
                if scenario == "normal" {
                    assert_eq!(
                        reader.next_record().unwrap().unwrap().payload,
                        b"record-data"
                    );
                } else {
                    let error = reader.next_record().unwrap_err();
                    assert!(matches!(error, TlsError::LocalAlert { alert, .. }
                        if alert.level == crate::error::AlertLevel::Fatal && alert.description == AlertDescription::BadRecordMac));
                }
            }
        }
    }

    #[test]
    fn tls12_ciphertext_limit_is_distinct_from_tls13() {
        let long_cbc_header = [23, 3, 3, 0x41, 0x20]; // 16672: 16384 content + CBC MAC/IV/long padding.
        let mut tls12 = RecordReader::new();
        tls12.set_tls12_keys(tls12_test_cipher(3));
        tls12.feed(&long_cbc_header);
        assert!(tls12.next_record().unwrap().is_none());
        let mut tls13 = tls13_reader();
        tls13.feed(&long_cbc_header);
        assert_eq!(
            alert_of(tls13.next_record()),
            Some(AlertDescription::RecordOverflow)
        );
        let mut tls12 = RecordReader::new();
        tls12.set_tls12_keys(tls12_test_cipher(3));
        tls12.feed(&[23, 3, 3, 0x48, 0x01]); // 18433: above the TLS 1.2 ciphertext ceiling.
        assert_eq!(
            alert_of(tls12.next_record()),
            Some(AlertDescription::RecordOverflow)
        );
    }

    #[test]
    fn tls13_record_version_policy_is_browser_specific() {
        for style in [
            TlsClientHelloStyle::Generic,
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            for version in [0x0301, 0x0303, 0x0304, 0x0403] {
                let mut reader = tls13_reader();
                reader.set_client_style(style);
                reader.feed(&tls13_record_at_version(&[0x42, 23], 0, version));
                if version == 0x0303 || style == TlsClientHelloStyle::Generic {
                    assert_eq!(reader.next_record().unwrap().unwrap().payload, [0x42]);
                } else {
                    let expected = if style == TlsClientHelloStyle::ChromiumBoringssl {
                        AlertDescription::ProtocolVersion
                    } else {
                        AlertDescription::BadRecordMac
                    };
                    assert_eq!(alert_of(reader.next_record()), Some(expected));
                }
            }
        }
    }

    #[test]
    fn tls12_record_versions_keep_nss_authenticated_compatibility() {
        for kind in 0..6 {
            for style in [
                TlsClientHelloStyle::Generic,
                TlsClientHelloStyle::ChromiumBoringssl,
                TlsClientHelloStyle::FirefoxNss,
            ] {
                for version in [0x0301u16, 0x0303, 0x0304, 0x0403] {
                    let mut aad = [0; 13];
                    aad[8] = 23;
                    aad[9..11].copy_from_slice(&version.to_be_bytes());
                    aad[12] = 1;
                    let encrypted = match tls12_test_cipher(kind) {
                        Tls12RecordCipher::Gcm(cipher) => cipher.encrypt(0, &aad, &[0x42]).unwrap(),
                        Tls12RecordCipher::Chacha20(cipher) => {
                            cipher.encrypt(0, &aad, &[0x42]).unwrap()
                        }
                        Tls12RecordCipher::Cbc(cipher) => cipher.encrypt(0, &aad, &[0x42]).unwrap(),
                    };
                    let mut record = vec![23];
                    record.extend_from_slice(&version.to_be_bytes());
                    record.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
                    record.extend_from_slice(&encrypted);
                    let mut reader = RecordReader::new();
                    reader.set_client_style(style);
                    reader.set_tls12_keys(tls12_test_cipher(kind));
                    reader.feed(&record);
                    if style == TlsClientHelloStyle::ChromiumBoringssl && version != 0x0303 {
                        assert_eq!(
                            alert_of(reader.next_record()),
                            Some(AlertDescription::ProtocolVersion)
                        );
                    } else {
                        assert_eq!(reader.next_record().unwrap().unwrap().payload, [0x42]);
                    }
                }
            }
        }
    }

    #[test]
    fn record_version_and_size_precedence_matches_browser_policy() {
        for tls12 in [false, true] {
            for style in [
                TlsClientHelloStyle::ChromiumBoringssl,
                TlsClientHelloStyle::FirefoxNss,
            ] {
                let mut reader = tls13_reader();
                if tls12 {
                    reader.set_tls12_keys(tls12_test_cipher(0));
                }
                reader.set_client_style(style);
                reader.feed(&[23, 4, 3, 0xff, 0xff]);
                let expected = if style == TlsClientHelloStyle::ChromiumBoringssl {
                    AlertDescription::ProtocolVersion
                } else {
                    AlertDescription::RecordOverflow
                };
                assert_eq!(alert_of(reader.next_record()), Some(expected));
            }
        }
        for version in [0x0301u16, 0x0303] {
            for length in [80u16, 81] {
                let mut reader = tls13_reader();
                reader.set_client_style(TlsClientHelloStyle::FirefoxNss);
                reader.set_own_record_size_limit(Some(64));
                let mut record = vec![23];
                record.extend_from_slice(&version.to_be_bytes());
                record.extend_from_slice(&length.to_be_bytes());
                record.resize(5 + length as usize, 0);
                reader.feed(&record);
                let expected = if length == 81 {
                    AlertDescription::RecordOverflow
                } else {
                    AlertDescription::BadRecordMac
                };
                assert_eq!(alert_of(reader.next_record()), Some(expected));
            }
        }
    }

    #[test]
    fn compatibility_ccs_version_policy_does_not_consume_aead_sequence() {
        for style in [
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            for version in [0x0301u16, 0x0403] {
                let mut reader = tls13_reader();
                reader.set_client_style(style);
                let mut record = vec![20];
                record.extend_from_slice(&version.to_be_bytes());
                record.extend_from_slice(&[0, 1, 1]);
                record.extend_from_slice(&tls13_record(&[0x42, 23]));
                reader.feed(&record);
                if style == TlsClientHelloStyle::ChromiumBoringssl {
                    assert_eq!(
                        alert_of(reader.next_record()),
                        Some(AlertDescription::ProtocolVersion)
                    );
                } else {
                    assert_eq!(reader.next_record().unwrap().unwrap().payload, [1]);
                    assert_eq!(reader.next_record().unwrap().unwrap().payload, [0x42]);
                }
            }
        }
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
