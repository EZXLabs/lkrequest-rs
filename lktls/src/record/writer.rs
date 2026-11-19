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

#[derive(Debug)]
pub enum WriteStop {
    Complete,
    NeedOutputCapacity,
    Terminal(TlsError),
}

#[derive(Debug)]
pub struct WriteProgress {
    pub accepted_plaintext: usize,
    pub committed_ciphertext: usize,
    pub stop: WriteStop,
}

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
    poisoned: bool,
    /// Write sequence number (for AEAD nonce construction).
    seq_num: u64,
    /// Cached per-key encryption budget, selected when keys are installed.
    record_limit: u64,
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
    tls12_session_state: Option<crate::session_store::client::Tls12SessionState>,
}

impl RecordWriter {
    /// Create a new record writer (plaintext mode — no encryption).
    pub fn new() -> Self {
        Self {
            poisoned: false,
            seq_num: 0,
            record_limit: u64::MAX,
            aead: None,
            tls12_cipher: None,
            flush_strategy: FlushStrategy::Immediate,
            coalesce_buf: Vec::new(),
            first_record_sent: false,
            peer_record_size_limit: None,
            tls12_session_state: None,
        }
    }

    pub(crate) fn set_tls12_session_state(
        &mut self,
        state: crate::session_store::client::Tls12SessionState,
    ) {
        self.tls12_session_state = Some(state);
    }

    pub(crate) fn invalidate_tls12_session(&self) {
        if let Some(state) = &self.tls12_session_state {
            state.invalidate();
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

    #[cfg(test)]
    pub(super) fn measurement_snapshot(&self) -> super::measurement::BufferSnapshot {
        super::measurement::BufferSnapshot::new(
            self.coalesce_buf.capacity(),
            self.coalesce_buf.len(),
            0,
        )
    }

    /// Install TLS 1.3 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_keys(&mut self, aead: Aead) {
        if self.poisoned {
            return;
        }
        self.record_limit = aead.algorithm().tls_record_limits().encrypt;
        self.aead = Some(aead);
        self.tls12_cipher = None;
        self.seq_num = 0;
    }

    /// Install TLS 1.2 encryption keys. All subsequent records will be encrypted.
    /// Resets the sequence number to 0.
    pub fn set_tls12_keys(&mut self, cipher: Tls12RecordCipher) {
        if self.poisoned {
            return;
        }
        self.record_limit = cipher.tls_record_limits().encrypt;
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
        let mut output = if self.flush_strategy == FlushStrategy::Coalesce {
            std::mem::take(&mut self.coalesce_buf)
        } else {
            Vec::new()
        };
        let progress = self.write_into(content_type, payload, &mut output, usize::MAX);
        match progress.stop {
            WriteStop::Terminal(error) => Err(error),
            WriteStop::NeedOutputCapacity => unreachable!("unbounded compatibility output"),
            WriteStop::Complete => {
                if self.flush_strategy == FlushStrategy::Coalesce {
                    self.coalesce_buf = output;
                    Ok(Vec::new())
                } else {
                    Ok(output)
                }
            }
        }
    }

    pub fn install_keys(&mut self, keys: super::WriteKeys) {
        match keys.0 {
            super::protection::Protection::Tls13(key) => self.set_keys(key),
            super::protection::Protection::Tls12(key) => self.set_tls12_keys(key),
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whole records still available under the active write key. The endpoint
    /// reserves the last one for an old-key KeyUpdate or a TLS 1.2 close alert.
    /// Plaintext has no cryptographic budget; poisoned writers always return 0.
    pub(crate) fn remaining_records(&self) -> u64 {
        if self.poisoned {
            0
        } else {
            self.record_limit.saturating_sub(self.seq_num)
        }
    }

    #[cfg(test)]
    pub(crate) fn set_sequence_for_test(&mut self, sequence: u64) {
        self.seq_num = sequence;
    }

    /// Append whole records to the endpoint's unsent ciphertext queue.
    ///
    /// The limit covers the entire physical Vec, including any consumed prefix
    /// retained by the caller's cursor. Capacity stops never consume a nonce.
    /// Terminal failures poison the writer and clear ALL unsent output,
    /// including earlier calls' ciphertext.
    /// Accepted plaintext on a terminal result is a prefix, not a delivery promise.
    /// This primitive ignores the legacy coalescing strategy.
    pub fn write_into(
        &mut self,
        content_type: u8,
        payload: &[u8],
        output: &mut Vec<u8>,
        limit: usize,
    ) -> WriteProgress {
        if content_type == content_type::ALERT && payload.first() == Some(&2) {
            self.invalidate_tls12_session();
        }
        let start = output.len();
        let mut accepted = 0;
        loop {
            if self.poisoned {
                return self.terminal(
                    output,
                    accepted,
                    TlsError::CryptoError("record writer is poisoned".into()),
                );
            }
            let chunk_len = (payload.len() - accepted).min(self.max_plaintext_chunk(content_type));
            let chunk = &payload[accepted..accepted + chunk_len];
            let length = self.encoded_len(chunk_len);
            if length > limit.saturating_sub(output.len()) {
                return WriteProgress {
                    accepted_plaintext: accepted,
                    committed_ciphertext: output.len() - start,
                    stop: WriteStop::NeedOutputCapacity,
                };
            }
            if self.remaining_records() == 0 {
                return self.terminal(
                    output,
                    accepted,
                    TlsError::CryptoError("write record key usage limit exhausted".into()),
                );
            }
            super::reserve_bounded(output, length, limit);
            if let Err(error) = self.encode_into(content_type, chunk, output) {
                return self.terminal(output, accepted, error);
            }
            accepted += chunk_len;
            if accepted == payload.len() {
                return WriteProgress {
                    accepted_plaintext: accepted,
                    committed_ciphertext: output.len() - start,
                    stop: WriteStop::Complete,
                };
            }
        }
    }

    fn terminal(
        &mut self,
        output: &mut Vec<u8>,
        accepted: usize,
        error: TlsError,
    ) -> WriteProgress {
        self.invalidate_tls12_session();
        self.poisoned = true;
        self.aead = None;
        self.tls12_cipher = None;
        self.coalesce_buf.clear();
        output.clear();
        WriteProgress {
            accepted_plaintext: accepted,
            committed_ciphertext: 0,
            stop: WriteStop::Terminal(error),
        }
    }

    fn encoded_len(&self, len: usize) -> usize {
        5 + if let Some(cipher) = &self.tls12_cipher {
            cipher.ciphertext_len(len)
        } else if self.aead.is_some() {
            len + 17
        } else {
            len
        }
    }

    fn encode_into(&mut self, ct: u8, payload: &[u8], output: &mut Vec<u8>) -> Result<()> {
        if let Some(cipher) = &self.tls12_cipher {
            let header = RecordHeader {
                content_type: ct,
                version: 0x0303,
                length: cipher.ciphertext_len(payload.len()) as u16,
            };
            output.extend_from_slice(&header.to_bytes());
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::RecordHeader, 5);
            let mut aad = [0; 13];
            aad[..8].copy_from_slice(&self.seq_num.to_be_bytes());
            aad[8] = ct;
            aad[9..11].copy_from_slice(&[3, 3]);
            aad[11..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            match cipher {
                Tls12RecordCipher::Gcm(cipher) => {
                    cipher.encrypt_into(self.seq_num, &aad, payload, output)?
                }
                Tls12RecordCipher::Chacha20(cipher) => {
                    cipher.encrypt_into(self.seq_num, &aad, payload, output)?
                }
                Tls12RecordCipher::Cbc(cipher) => {
                    cipher.encrypt_into(self.seq_num, &aad, payload, output)?
                }
            }
            self.seq_num += 1;
        } else if let Some(aead) = &self.aead {
            let header = RecordHeader {
                content_type: content_type::APPLICATION_DATA,
                version: 0x0303,
                length: (payload.len() + 17) as u16,
            }
            .to_bytes();
            output.extend_from_slice(&header);
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::RecordHeader, header.len());
            let start = output.len();
            output.extend_from_slice(payload);
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::PlaintextSeal, payload.len());
            output.push(ct);
            let tag = aead.seal_in_place(self.seq_num, &header, &mut output[start..])?;
            output.extend_from_slice(&tag);
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::AuthTag, tag.len());
            self.seq_num += 1;
        } else {
            let header = RecordHeader {
                content_type: ct,
                version: if self.first_record_sent {
                    0x0303
                } else {
                    0x0301
                },
                length: payload.len() as u16,
            };
            output.extend_from_slice(&header.to_bytes());
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::RecordHeader, 5);
            output.extend_from_slice(payload);
            #[cfg(test)]
            super::measurement::copied(super::measurement::CopySite::PlaintextSeal, payload.len());
            self.first_record_sent = true;
        }
        Ok(())
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
    fn usage_limit_aes_gcm_rejects_before_sealing_in_both_tls_versions() {
        for tls12 in [false, true] {
            for key_len in [16, 32] {
                let mut writer = RecordWriter::new();
                if tls12 {
                    writer.set_tls12_keys(Tls12RecordCipher::Gcm(
                        Tls12GcmCipher::new(&vec![3; key_len], &[4; 4], key_len == 32).unwrap(),
                    ));
                } else {
                    let algorithm = if key_len == 16 {
                        AeadAlgorithm::Aes128Gcm
                    } else {
                        AeadAlgorithm::Aes256Gcm
                    };
                    writer
                        .set_keys(AeadCipher::new(algorithm, &vec![3; key_len], &[4; 12]).unwrap());
                }
                writer.set_sequence_for_test(1 << 24);
                let mut output = vec![0xab; 10];
                let progress = writer.write_into(23, b"exhausted", &mut output, usize::MAX);
                assert!(
                    matches!(progress.stop, WriteStop::Terminal(_)),
                    "GCM record budget was not enforced"
                );
                assert_eq!(progress.accepted_plaintext, 0);
                assert!(output.is_empty());
                assert!(writer.is_poisoned());
            }
        }
    }

    #[test]
    fn usage_limit_terminal_preserves_prefix_and_discards_all_unsent_records() {
        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[3; 16], &[4; 12]).unwrap());
        writer.set_sequence_for_test((1 << 24) - 1);
        let mut output = vec![0xab; 10];
        let progress = writer.write_into(
            23,
            &vec![7; MAX_RECORD_PAYLOAD + 1],
            &mut output,
            usize::MAX,
        );
        assert!(
            matches!(progress.stop, WriteStop::Terminal(_)),
            "GCM multi-record call crossed its budget"
        );
        assert_eq!(progress.accepted_plaintext, MAX_RECORD_PAYLOAD);
        assert_eq!(progress.committed_ciphertext, 0);
        assert!(output.is_empty());
        assert!(writer.is_poisoned());
    }

    #[test]
    fn exhausted_writer_cannot_be_revived_by_new_keys() {
        let mut writer = RecordWriter::new();
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[3; 16], &[4; 12]).unwrap());
        writer.seq_num = u64::MAX;
        assert!(writer.write_record(23, b"fail").is_err());
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[5; 16], &[6; 12]).unwrap());
        assert!(writer.write_record(23, b"retry").is_err());
    }

    #[test]
    fn terminal_write_reports_prefix_but_discards_unsent_output() {
        let mut writer = RecordWriter::new();
        writer.set_keys(
            AeadCipher::new(AeadAlgorithm::Chacha20Poly1305, &[3; 32], &[4; 12]).unwrap(),
        );
        writer.seq_num = u64::MAX - 1;
        let mut output = vec![0xab; 10];
        let progress = writer.write_into(
            23,
            &vec![7; MAX_RECORD_PAYLOAD + 1],
            &mut output,
            usize::MAX,
        );
        assert_eq!(progress.accepted_plaintext, MAX_RECORD_PAYLOAD);
        assert_eq!(progress.committed_ciphertext, 0);
        assert!(matches!(progress.stop, WriteStop::Terminal(_)));
        assert!(output.is_empty());
        assert!(writer.is_poisoned());
        assert!(matches!(
            writer
                .write_into(23, b"retry", &mut output, usize::MAX)
                .stop,
            WriteStop::Terminal(_)
        ));
    }

    #[test]
    fn usage_limit_capacity_stop_preserves_the_last_record_and_nonce() {
        for tls12 in [false, true] {
            let mut writer = RecordWriter::new();
            if tls12 {
                writer.set_tls12_keys(Tls12RecordCipher::Gcm(
                    Tls12GcmCipher::new(&[3; 16], &[4; 4], false).unwrap(),
                ));
            } else {
                writer.set_keys(
                    AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[3; 16], &[4; 12]).unwrap(),
                );
            }
            writer.set_sequence_for_test((1 << 24) - 1);
            let mut output = Vec::new();
            let length = writer.encoded_len(5);
            let progress = writer.write_into(22, &[24, 0, 0, 1, 0], &mut output, length - 1);
            assert!(matches!(progress.stop, WriteStop::NeedOutputCapacity));
            assert_eq!(progress.accepted_plaintext, 0);
            assert_eq!(writer.remaining_records(), 1);
            assert!(output.is_empty());
            assert!(!writer.is_poisoned());
            let progress = writer.write_into(22, &[24, 0, 0, 1, 0], &mut output, length);
            assert!(matches!(progress.stop, WriteStop::Complete));
            assert_eq!(progress.accepted_plaintext, 5);
            assert_eq!(writer.remaining_records(), 0);
            assert_eq!(output.len(), length);
            assert!(!writer.is_poisoned());
        }
    }

    #[test]
    fn usage_limit_exhaustion_cannot_be_revived_by_a_different_cipher() {
        let mut writer = RecordWriter::new();
        writer.set_flush_strategy(FlushStrategy::Coalesce);
        writer.set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[3; 16], &[4; 12]).unwrap());
        writer.write_record(23, b"unsent").unwrap();
        writer.set_sequence_for_test(1 << 24);
        assert!(writer.write_record(23, b"exhausted").is_err());
        assert!(writer.flush().is_empty());
        writer.install_keys(super::super::WriteKeys::tls12(Tls12RecordCipher::Chacha20(
            crate::crypto::tls12_cipher::Tls12Chacha20Cipher::new(&[5; 32], &[6; 12]).unwrap(),
        )));
        assert_eq!(writer.remaining_records(), 0);
        assert!(writer.write_record(23, b"retry").is_err());
    }

    #[test]
    fn usage_limit_chacha_and_cbc_retain_the_sequence_ceiling() {
        use crate::crypto::tls12_cipher::{CbcMacAlgorithm, Tls12CbcCipher, Tls12Chacha20Cipher};
        for kind in 0..3 {
            let mut writer = RecordWriter::new();
            match kind {
                0 => writer.set_keys(
                    AeadCipher::new(AeadAlgorithm::Chacha20Poly1305, &[3; 32], &[4; 12]).unwrap(),
                ),
                1 => writer.set_tls12_keys(Tls12RecordCipher::Chacha20(
                    Tls12Chacha20Cipher::new(&[3; 32], &[4; 12]).unwrap(),
                )),
                _ => writer.set_tls12_keys(Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                    &[3; 16],
                    &[4; 20],
                    CbcMacAlgorithm::HmacSha1,
                ))),
            }
            assert_eq!(writer.remaining_records(), u64::MAX);
            writer.set_sequence_for_test(u64::MAX - 1);
            assert_eq!(writer.remaining_records(), 1);
            assert!(!writer.write_record(23, b"last").unwrap().is_empty());
            assert_eq!(writer.remaining_records(), 0);
            assert!(writer.write_record(23, b"overflow").is_err());
            assert!(writer.is_poisoned());
        }
    }

    #[test]
    fn usage_limit_key_installation_resets_only_its_direction() {
        use crate::record::{ReadKeys, WriteKeys};
        let mut writer = RecordWriter::new();
        let mut reader = RecordReader::new();
        writer
            .install_keys(WriteKeys::tls13(AeadAlgorithm::Aes128Gcm, &[3; 16], &[4; 12]).unwrap());
        reader.install_keys(ReadKeys::tls13(AeadAlgorithm::Aes128Gcm, &[5; 16], &[6; 12]).unwrap());
        writer.set_sequence_for_test((1 << 24) - 1);
        reader.set_sequence_for_test(9);

        writer
            .install_keys(WriteKeys::tls13(AeadAlgorithm::Aes128Gcm, &[7; 16], &[8; 12]).unwrap());
        assert_eq!(writer.remaining_records(), 1 << 24);
        let mut peer_writer = RecordWriter::new();
        peer_writer
            .set_keys(AeadCipher::new(AeadAlgorithm::Aes128Gcm, &[5; 16], &[6; 12]).unwrap());
        peer_writer.set_sequence_for_test(9);
        reader.feed(&peer_writer.write_record(23, b"old read epoch").unwrap());
        assert_eq!(
            reader.next_record().unwrap().unwrap().payload,
            b"old read epoch"
        );

        writer.set_sequence_for_test(7);
        reader
            .install_keys(ReadKeys::tls13(AeadAlgorithm::Aes256Gcm, &[9; 32], &[10; 12]).unwrap());
        assert_eq!(writer.remaining_records(), (1 << 24) - 7);
        peer_writer
            .set_keys(AeadCipher::new(AeadAlgorithm::Aes256Gcm, &[9; 32], &[10; 12]).unwrap());
        reader.feed(&peer_writer.write_record(23, b"new read epoch").unwrap());
        assert_eq!(
            reader.next_record().unwrap().unwrap().payload,
            b"new read epoch"
        );
    }

    #[test]
    fn provider_failure_discards_legacy_coalesced_records() {
        use crate::crypto::tls12_cipher::{CbcMacAlgorithm, Tls12CbcCipher};
        let mut writer = RecordWriter::new();
        writer.set_flush_strategy(FlushStrategy::Coalesce);
        writer.write_record(22, b"hello").unwrap();
        writer.set_tls12_keys(Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
            &[1; 15],
            &[2; 20],
            CbcMacAlgorithm::HmacSha1,
        )));
        assert!(writer.write_record(23, b"fail").is_err());
        assert!(writer.is_poisoned());
        assert!(writer.flush().is_empty());
    }

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
