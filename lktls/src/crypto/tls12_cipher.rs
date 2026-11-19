//! TLS 1.2 record-layer ciphers.
//!
//! TLS 1.2 supports two families of cipher suites for record protection:
//!
//! - **GCM (AEAD)**: Modern, secure. Uses 4-byte implicit IV + 8-byte explicit nonce.
//!   Examples: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
//!
//! - **CBC + HMAC**: Legacy. Uses MAC-then-encrypt, or negotiated RFC 7366
//!   Encrypt-then-MAC, with TLS block cipher padding.
//!   Examples: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)
//!
//! This module abstracts both behind a common [`Tls12CipherSuite`] enum.

use crate::error::{Result, TlsError};

/// Key exchange algorithm used by a TLS 1.2 cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12KeyExchange {
    /// ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) — provides forward secrecy.
    Ecdhe,
    /// Static RSA — client encrypts pre-master secret with server's RSA public key.
    Rsa,
}

/// A TLS 1.2 cipher suite's record-protection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    /// TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A), legacy interoperability.
    RsaTripleDesCbcSha,
    /// TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xC008), legacy interoperability.
    EcdheEcdsaTripleDesCbcSha,
    /// TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xC012), legacy interoperability.
    EcdheRsaTripleDesCbcSha,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)
    EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
    EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)
    EcdheEcdsaChacha20Poly1305,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
    EcdheRsaChacha20Poly1305,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009).
    EcdheEcdsaAes128CbcSha,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xC00A).
    EcdheEcdsaAes256CbcSha,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023).
    EcdheEcdsaAes128CbcSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xC024).
    EcdheEcdsaAes256CbcSha384,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013) — legacy CBC
    EcdheRsaAes128CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014) — legacy CBC
    EcdheRsaAes256CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027) — legacy CBC
    EcdheRsaAes128CbcSha256,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028) — legacy CBC
    EcdheRsaAes256CbcSha384,
    /// TLS_RSA_WITH_AES_256_CBC_SHA (0x0035) — static RSA key exchange, legacy CBC
    RsaAes256CbcSha,
    /// TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) — static RSA key exchange, legacy CBC
    RsaAes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D) — static RSA key exchange, legacy CBC
    RsaAes256CbcSha256,
    /// TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C) — static RSA key exchange, legacy CBC
    RsaAes128CbcSha256,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C) — static RSA key exchange, GCM
    RsaAes128GcmSha256,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D) — static RSA key exchange, GCM
    RsaAes256GcmSha384,
}

impl Tls12CipherSuite {
    /// Resolve from a TLS cipher suite code point.
    pub fn from_code_point(code: u16) -> Option<Self> {
        super::suites::tls12_suite(code)
    }

    pub(crate) fn descriptor(self) -> &'static super::suites::Tls12Suite {
        super::suites::tls12_descriptor(self)
    }

    /// Return the TLS cipher suite code point.
    pub fn code_point(self) -> u16 {
        self.descriptor().code
    }

    /// Key exchange algorithm used by this cipher suite.
    pub fn key_exchange(&self) -> Tls12KeyExchange {
        self.descriptor().key_exchange
    }

    /// Whether this suite uses AEAD (GCM/ChaCha20).
    pub fn is_aead(&self) -> bool {
        self.descriptor().protection.aead().is_some()
    }

    /// Whether this suite uses CBC + HMAC.
    pub fn is_cbc(&self) -> bool {
        matches!(
            self.descriptor().protection,
            super::suites::Tls12Protection::AesCbc { .. }
                | super::suites::Tls12Protection::TripleDesCbc
        )
    }

    /// Encryption key length in bytes.
    pub fn enc_key_len(&self) -> usize {
        self.descriptor().protection.key_len()
    }

    /// MAC key length (0 for AEAD suites).
    pub fn mac_key_len(&self) -> usize {
        self.descriptor().protection.mac_len()
    }

    /// Fixed IV length in the legacy key-block API (4 GCM, 16 AES-CBC,
    /// 8 3DES-CBC, 12 ChaCha20).
    pub fn fixed_iv_len(&self) -> usize {
        self.descriptor().protection.fixed_iv_len()
    }

    /// The PRF algorithm for this cipher suite.
    pub fn prf_algorithm(&self) -> super::prf::PrfAlgorithm {
        self.descriptor().prf
    }

    /// The hash algorithm for transcript hashing.
    pub fn hash_algorithm(&self) -> super::hkdf::HkdfAlgorithm {
        self.descriptor().hash()
    }
}

/// TLS 1.2 record protection, also re-exported at its original record-layer path.
pub enum Tls12RecordCipher {
    /// AES-GCM with a four-byte implicit IV and eight-byte explicit nonce.
    Gcm(Tls12GcmCipher),
    /// ChaCha20-Poly1305 with the sequence number mixed into its IV.
    Chacha20(Tls12Chacha20Cipher),
    /// AES-CBC or legacy 3DES-CBC with HMAC.
    Cbc(Tls12CbcCipher),
}

impl Tls12RecordCipher {
    pub(crate) fn tls_record_limits(&self) -> super::suites::TlsRecordLimits {
        match self {
            Self::Gcm(_) => super::suites::TlsRecordLimits::AES_GCM,
            Self::Chacha20(_) | Self::Cbc(_) => super::suites::TlsRecordLimits::SEQUENCE_ONLY,
        }
    }

    pub(crate) fn ciphertext_len(&self, plaintext_len: usize) -> usize {
        match self {
            Self::Gcm(_) => plaintext_len + 24,
            Self::Chacha20(_) => plaintext_len + 16,
            Self::Cbc(cbc) => {
                let mac_len = cbc.mac_algorithm.mac_len();
                let block = cbc.block_size;
                match cbc.mac_mode {
                    CbcMacMode::MacThenEncrypt => {
                        block + ((plaintext_len + mac_len) / block + 1) * block
                    }
                    CbcMacMode::EncryptThenMac => {
                        block + (plaintext_len / block + 1) * block + mac_len
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GCM cipher for TLS 1.2
// ---------------------------------------------------------------------------

/// TLS 1.2 GCM cipher — uses a 4-byte implicit IV + 8-byte explicit nonce.
///
/// The nonce construction differs from TLS 1.3:
/// - TLS 1.2 GCM: nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes, sent with record)
/// - TLS 1.3: nonce = iv (12 bytes) XOR seq_num
pub struct Tls12GcmCipher {
    key: aws_lc_rs::aead::LessSafeKey,
    /// 4-byte implicit IV (from key block).
    implicit_iv: [u8; 4],
}

impl Tls12GcmCipher {
    /// Create a new TLS 1.2 GCM cipher.
    ///
    /// * `key` — encryption key (16 or 32 bytes)
    /// * `implicit_iv` — 4-byte implicit IV from key block
    /// * `is_aes_256` — true for AES-256-GCM, false for AES-128-GCM
    pub fn new(key: &[u8], implicit_iv: &[u8; 4], is_aes_256: bool) -> Result<Self> {
        let algo = if is_aes_256 {
            &aws_lc_rs::aead::AES_256_GCM
        } else {
            &aws_lc_rs::aead::AES_128_GCM
        };

        let opening = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create GCM opening key".into()))?;

        Ok(Self {
            key: aws_lc_rs::aead::LessSafeKey::new(opening),
            implicit_iv: *implicit_iv,
        })
    }

    /// Encrypt a TLS 1.2 record.
    ///
    /// Returns: 8-byte explicit_nonce || ciphertext || 16-byte tag
    ///
    /// The AAD for TLS 1.2 is: seq_num(8) || content_type(1) || version(2) || length(2)
    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(8 + plaintext.len() + 16);
        self.encrypt_into(seq_num, aad, plaintext, &mut output)?;
        Ok(output)
    }

    /// Append a payload, reusing the caller's reserved storage.
    pub fn encrypt_into(
        &self,
        seq_num: u64,
        aad: &[u8],
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let nonce = self.nonce(&seq_num.to_be_bytes());
        output.extend_from_slice(&seq_num.to_be_bytes());
        let start = output.len();
        output.extend_from_slice(plaintext);
        #[cfg(test)]
        crate::record::measure_plaintext_copy(plaintext.len());
        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aws_lc_rs::aead::Aad::from(aad),
                &mut output[start..],
            )
            .map_err(|_| TlsError::CryptoError("TLS 1.2 GCM encryption failed".into()))?;
        output.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn nonce(&self, explicit: &[u8]) -> aws_lc_rs::aead::Nonce {
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.implicit_iv);
        nonce[4..].copy_from_slice(explicit);
        aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce)
    }

    /// Decrypt an explicit-nonce-prefixed TLS 1.2 record.
    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut output = ciphertext.to_vec();
        self.decrypt_in_place(aad, &mut output)?;
        Ok(output)
    }

    pub fn decrypt_in_place(&self, aad: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        if payload.len() < 24 {
            return Err(TlsError::CryptoError("TLS 1.2 GCM record too short".into()));
        }
        let nonce = self.nonce(&payload[..8]);
        let len = self
            .key
            .open_within(nonce, aws_lc_rs::aead::Aad::from(aad), payload, 8..)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 GCM decryption failed".into()))?
            .len();
        payload.truncate(len);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 cipher for TLS 1.2
// ---------------------------------------------------------------------------

/// TLS 1.2 ChaCha20-Poly1305 cipher.
///
/// Uses the same nonce construction as TLS 1.3 (XOR with seq_num) per RFC 7905.
pub struct Tls12Chacha20Cipher {
    key: aws_lc_rs::aead::LessSafeKey,
    /// 12-byte IV (from key block).
    iv: [u8; 12],
}

impl Tls12Chacha20Cipher {
    pub fn new(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self> {
        let algo = &aws_lc_rs::aead::CHACHA20_POLY1305;
        let opening = aws_lc_rs::aead::UnboundKey::new(algo, key)
            .map_err(|_| TlsError::CryptoError("Failed to create ChaCha20 key".into()))?;

        Ok(Self {
            key: aws_lc_rs::aead::LessSafeKey::new(opening),
            iv: *iv,
        })
    }

    fn make_nonce(&self, seq_num: u64) -> aws_lc_rs::aead::Nonce {
        let mut nonce = self.iv;
        let seq_bytes = seq_num.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce)
    }

    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aws_lc_rs::aead::Aad::from(aad), &mut buf)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 encryption failed".into()))?;
        Ok(buf)
    }

    pub fn decrypt(&self, seq_num: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        let mut buf = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aws_lc_rs::aead::Aad::from(aad), &mut buf)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 decryption failed".into()))?;
        let len = plaintext.len();
        buf.truncate(len);
        Ok(buf)
    }
    pub fn encrypt_into(
        &self,
        seq_num: u64,
        aad: &[u8],
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let start = output.len();
        output.extend_from_slice(plaintext);
        #[cfg(test)]
        crate::record::measure_plaintext_copy(plaintext.len());
        let tag = self
            .key
            .seal_in_place_separate_tag(
                self.make_nonce(seq_num),
                aws_lc_rs::aead::Aad::from(aad),
                &mut output[start..],
            )
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 encryption failed".into()))?;
        output.extend_from_slice(tag.as_ref());
        Ok(())
    }

    pub fn decrypt_in_place(&self, seq_num: u64, aad: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        let len = self
            .key
            .open_in_place(
                self.make_nonce(seq_num),
                aws_lc_rs::aead::Aad::from(aad),
                payload,
            )
            .map_err(|_| TlsError::CryptoError("TLS 1.2 ChaCha20 decryption failed".into()))?
            .len();
        payload.truncate(len);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CBC + HMAC cipher for TLS 1.2 (using RustCrypto `aes` crate)
// ---------------------------------------------------------------------------

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// TLS 1.2 CBC + HMAC cipher.
///
/// Uses MAC-then-encrypt (RFC 5246 Section 6.2.3.2):
/// 1. Compute HMAC over `seq_num || content_type || version || length || plaintext`
/// 2. Assemble: `plaintext || mac || tls_padding`
/// 3. Generate a random, block-sized IV
/// 4. CBC encrypt the assembled data
/// 5. Output: `iv || encrypted_data` (16-byte IV for AES, 8-byte IV for 3DES)
pub struct Tls12CbcCipher {
    /// Encryption key bytes (16/32 for AES, 24 for legacy 3DES).
    enc_key: Vec<u8>,
    /// MAC key bytes (for HMAC-SHA1 or HMAC-SHA256/384).
    // The cached backend HMAC state is over 1 KiB; keep AEAD record owners small.
    mac_key: Box<aws_lc_rs::hmac::Key>,
    /// HMAC algorithm to use.
    mac_algorithm: CbcMacAlgorithm,
    /// AES uses 16-byte blocks; 3DES uses 8-byte blocks.
    block_size: usize,
    mac_mode: CbcMacMode,
}

/// CBC authentication order negotiated for this connection (RFC 7366).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CbcMacMode {
    /// Original TLS record format; used when Encrypt-then-MAC was not negotiated.
    #[default]
    MacThenEncrypt,
    /// Authenticate the explicit IV and ciphertext before decrypting.
    EncryptThenMac,
}

/// MAC algorithm used with CBC cipher suites.
#[derive(Debug, Clone, Copy)]
pub enum CbcMacAlgorithm {
    /// HMAC-SHA1 (20-byte MAC)
    HmacSha1,
    /// HMAC-SHA256 (32-byte MAC)
    HmacSha256,
    /// HMAC-SHA384 (48-byte MAC)
    HmacSha384,
}

impl CbcMacAlgorithm {
    pub fn mac_len(&self) -> usize {
        match self {
            CbcMacAlgorithm::HmacSha1 => 20,
            CbcMacAlgorithm::HmacSha256 => 32,
            CbcMacAlgorithm::HmacSha384 => 48,
        }
    }

    fn hmac_algorithm_ref(&self) -> aws_lc_rs::hmac::Algorithm {
        match self {
            CbcMacAlgorithm::HmacSha1 => aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            CbcMacAlgorithm::HmacSha256 => aws_lc_rs::hmac::HMAC_SHA256,
            CbcMacAlgorithm::HmacSha384 => aws_lc_rs::hmac::HMAC_SHA384,
        }
    }
}

impl Tls12CbcCipher {
    /// Create a new TLS 1.2 CBC cipher.
    pub fn new(enc_key: &[u8], mac_key: &[u8], mac_algorithm: CbcMacAlgorithm) -> Self {
        Self::new_with_mode(enc_key, mac_key, mac_algorithm, CbcMacMode::MacThenEncrypt)
    }

    /// Create a cipher using the negotiated CBC authentication order.
    pub fn new_with_mode(
        enc_key: &[u8],
        mac_key: &[u8],
        mac_algorithm: CbcMacAlgorithm,
        mac_mode: CbcMacMode,
    ) -> Self {
        Self {
            enc_key: enc_key.to_vec(),
            mac_key: Box::new(aws_lc_rs::hmac::Key::new(
                mac_algorithm.hmac_algorithm_ref(),
                mac_key,
            )),
            mac_algorithm,
            block_size: if enc_key.len() == 24 { 8 } else { 16 },
            mac_mode,
        }
    }

    fn compute_tag(&self, aad: &[u8], payload: &[u8]) -> aws_lc_rs::hmac::Tag {
        let mut ctx = aws_lc_rs::hmac::Context::with_key(&self.mac_key);
        ctx.update(aad);
        ctx.update(payload);
        ctx.sign()
    }

    #[cfg(test)]
    fn compute_mac(&self, aad: &[u8], payload: &[u8]) -> Vec<u8> {
        self.compute_tag(aad, payload).as_ref().to_vec()
    }

    /// Encrypt a TLS 1.2 CBC record using the negotiated MAC order.
    pub fn encrypt(&self, seq_num: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.encrypt_into(seq_num, aad, plaintext, &mut output)?;
        Ok(output)
    }

    /// Seal directly into reusable storage, with fresh explicit IV and minimal padding.
    pub fn encrypt_into(
        &self,
        _seq_num: u64,
        aad: &[u8],
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut iv = [0; 16];
        let iv = &mut iv[..self.block_size];
        aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), iv)
            .map_err(|_| TlsError::CryptoError("Failed to generate CBC IV".into()))?;
        let record_start = output.len();
        output.extend_from_slice(iv);
        let content_start = output.len();
        output.extend_from_slice(plaintext);
        if self.mac_mode == CbcMacMode::MacThenEncrypt {
            output.extend_from_slice(self.compute_tag(aad, plaintext).as_ref());
        }
        let padding = self.block_size - (output.len() - content_start) % self.block_size;
        output.resize(output.len() + padding, (padding - 1) as u8);
        self.cbc_encrypt_in_place(iv, &mut output[content_start..])?;
        if self.mac_mode == CbcMacMode::EncryptThenMac {
            let mac_aad = Self::aad_with_length(aad, output.len() - record_start)?;
            let tag = self.compute_tag(&mac_aad, &output[record_start..]);
            output.extend_from_slice(tag.as_ref());
        }
        Ok(())
    }

    /// Authenticate and decrypt a TLS 1.2 CBC record.
    ///
    /// Legacy MAC-then-encrypt retains its length-dependent MAC/padding work;
    /// it is not a constant-time TLS CBC implementation.
    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut output = ciphertext.to_vec();
        self.decrypt_in_place(aad, &mut output)?;
        Ok(output)
    }

    /// On failure the caller must discard this buffer; it may contain invalid plaintext.
    pub fn decrypt_in_place(&self, aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
        if self.mac_mode == CbcMacMode::EncryptThenMac {
            let mac_len = self.mac_algorithm.mac_len();
            if data.len() < 2 * self.block_size + mac_len {
                return Err(TlsError::CryptoError("TLS 1.2 EtM record too short".into()));
            }
            let encrypted_len = data.len() - mac_len;
            let mac_aad = Self::aad_with_length(aad, encrypted_len)?;
            let expected = self.compute_tag(&mac_aad, &data[..encrypted_len]);
            aws_lc_rs::constant_time::verify_slices_are_equal(
                expected.as_ref(),
                &data[encrypted_len..],
            )
            .map_err(|_| TlsError::CryptoError("TLS 1.2 EtM authentication failed".into()))?;
            data.truncate(encrypted_len);
        }
        if data.len() < 2 * self.block_size
            || !(data.len() - self.block_size).is_multiple_of(self.block_size)
        {
            return Err(TlsError::CryptoError(
                "invalid TLS 1.2 CBC ciphertext length".into(),
            ));
        }
        let mut iv = [0; 16];
        iv[..self.block_size].copy_from_slice(&data[..self.block_size]);
        self.cbc_decrypt_in_place(&iv[..self.block_size], &mut data[self.block_size..])?;
        let decrypted = &data[self.block_size..];
        let padding_length = decrypted[decrypted.len() - 1] as usize;
        let total_padding = padding_length + 1;
        let mac_len = if self.mac_mode == CbcMacMode::MacThenEncrypt {
            self.mac_algorithm.mac_len()
        } else {
            0
        };
        if decrypted.len() < total_padding + mac_len {
            return Err(TlsError::CryptoError(
                "TLS 1.2 CBC record too short after decrypt".into(),
            ));
        }
        let content_end = decrypted.len() - total_padding;
        let plaintext_end = content_end - mac_len;
        let mut padding_bad = 0u8;
        for byte in &decrypted[content_end..] {
            padding_bad |= byte ^ padding_length as u8;
        }
        let mac_bad = if self.mac_mode == CbcMacMode::MacThenEncrypt {
            let mac_aad = Self::aad_with_length(aad, plaintext_end)?;
            let expected = self.compute_tag(&mac_aad, &decrypted[..plaintext_end]);
            aws_lc_rs::constant_time::verify_slices_are_equal(
                expected.as_ref(),
                &decrypted[plaintext_end..content_end],
            )
            .is_err()
        } else {
            false
        };
        if padding_bad != 0 || mac_bad {
            return Err(TlsError::CryptoError(
                "TLS 1.2 CBC MAC or padding verification failed".into(),
            ));
        }
        data.copy_within(self.block_size..self.block_size + plaintext_end, 0);
        data.truncate(plaintext_end);
        Ok(())
    }

    fn aad_with_length(aad: &[u8], length: usize) -> Result<[u8; 13]> {
        let mut result: [u8; 13] = aad
            .try_into()
            .map_err(|_| TlsError::CryptoError("TLS 1.2 CBC AAD must contain 13 bytes".into()))?;
        let length = u16::try_from(length)
            .map_err(|_| TlsError::CryptoError("TLS 1.2 CBC ciphertext too large".into()))?;
        result[11..].copy_from_slice(&length.to_be_bytes());
        Ok(result)
    }

    #[cfg(test)]
    fn cbc_encrypt(&self, iv: &[u8; 16], data: &mut [u8]) -> Result<Vec<u8>> {
        self.cbc_encrypt_in_place(iv, data)?;
        Ok(data.to_vec())
    }

    #[allow(deprecated)] // Only negotiated, advertised legacy 3DES suites reach this branch.
    fn cbc_encrypt_in_place(&self, iv: &[u8], data: &mut [u8]) -> Result<()> {
        if self.enc_key.len() == 24 {
            use aws_lc_rs::cipher::{
                EncryptingKey, EncryptionContext, UnboundCipherKey, DES_EDE3_FOR_LEGACY_USE_ONLY,
            };
            let mut encrypt = || {
                let key = UnboundCipherKey::new(&DES_EDE3_FOR_LEGACY_USE_ONLY, &self.enc_key)?;
                EncryptingKey::cbc(key)?.less_safe_encrypt(
                    data,
                    EncryptionContext::Iv64(aws_lc_rs::iv::FixedLength::from(
                        <[u8; 8]>::try_from(iv).unwrap(),
                    )),
                )?;
                Ok::<_, aws_lc_rs::error::Unspecified>(())
            };
            return encrypt()
                .map_err(|_| TlsError::CryptoError("3DES-CBC encryption failed".into()));
        }
        let len = data.len();
        match self.enc_key.len() {
            16 => Aes128CbcEnc::new_from_slices(&self.enc_key, iv)
                .unwrap()
                .encrypt_padded_mut::<NoPadding>(data, len),
            32 => Aes256CbcEnc::new_from_slices(&self.enc_key, iv)
                .unwrap()
                .encrypt_padded_mut::<NoPadding>(data, len),
            other => {
                return Err(TlsError::CryptoError(format!(
                    "Invalid CBC key length: {other}"
                )))
            }
        }
        .map_err(|_| TlsError::CryptoError("AES-CBC encryption failed".into()))?;
        Ok(())
    }

    #[allow(deprecated)]
    fn cbc_decrypt_in_place(&self, iv: &[u8], data: &mut [u8]) -> Result<()> {
        if self.enc_key.len() == 24 {
            use aws_lc_rs::cipher::{
                DecryptingKey, DecryptionContext, UnboundCipherKey, DES_EDE3_FOR_LEGACY_USE_ONLY,
            };
            let mut decrypt = || {
                let key = UnboundCipherKey::new(&DES_EDE3_FOR_LEGACY_USE_ONLY, &self.enc_key)?;
                DecryptingKey::cbc(key)?.decrypt(
                    data,
                    DecryptionContext::Iv64(aws_lc_rs::iv::FixedLength::from(
                        <[u8; 8]>::try_from(iv).unwrap(),
                    )),
                )?;
                Ok::<_, aws_lc_rs::error::Unspecified>(())
            };
            return decrypt()
                .map_err(|_| TlsError::CryptoError("3DES-CBC decryption failed".into()));
        }
        match self.enc_key.len() {
            16 => Aes128CbcDec::new_from_slices(&self.enc_key, iv)
                .unwrap()
                .decrypt_padded_mut::<NoPadding>(data),
            32 => Aes256CbcDec::new_from_slices(&self.enc_key, iv)
                .unwrap()
                .decrypt_padded_mut::<NoPadding>(data),
            other => {
                return Err(TlsError::CryptoError(format!(
                    "Invalid CBC key length: {other}"
                )))
            }
        }
        .map_err(|_| TlsError::CryptoError("AES-CBC decryption failed".into()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_des_cbc_matches_independent_openssl_vector() {
        let cipher = Tls12CbcCipher::new(
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ],
            &[0x42; 20],
            CbcMacAlgorithm::HmacSha1,
        );
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let original = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut data = original;
        cipher.cbc_encrypt_in_place(&iv, &mut data).unwrap();
        assert_eq!(
            data,
            [
                0x8a, 0xe5, 0xaa, 0x55, 0xc7, 0x8f, 0x0c, 0x99, 0xd7, 0xd3, 0x38, 0x51, 0xf9, 0x1e,
                0x3a, 0x87
            ]
        );
        cipher.cbc_decrypt_in_place(&iv, &mut data).unwrap();
        assert_eq!(data, original);
        for mode in [CbcMacMode::MacThenEncrypt, CbcMacMode::EncryptThenMac] {
            let key: Vec<u8> = (1..=24).collect();
            let cipher =
                Tls12CbcCipher::new_with_mode(&key, &[0x73; 20], CbcMacAlgorithm::HmacSha1, mode);
            for length in 0..65 {
                let payload = vec![0x42; length];
                let mut aad = [0; 13];
                aad[8..11].copy_from_slice(&[23, 3, 3]);
                aad[11..].copy_from_slice(&(length as u16).to_be_bytes());
                let encrypted = cipher.encrypt(0, &aad, &payload).unwrap();
                assert_eq!(cipher.decrypt(&aad, &encrypted).unwrap(), payload);
                let mut corrupt = encrypted;
                corrupt[0] ^= 1;
                assert!(cipher.decrypt(&aad, &corrupt).is_err());
            }
        }
    }

    #[test]
    fn cbc_uses_minimal_padding_at_every_block_boundary() {
        for key_length in [16, 32] {
            for mac_algorithm in [
                CbcMacAlgorithm::HmacSha1,
                CbcMacAlgorithm::HmacSha256,
                CbcMacAlgorithm::HmacSha384,
            ] {
                let cipher = Tls12CbcCipher::new(
                    &vec![0x42; key_length],
                    &vec![0x24; mac_algorithm.mac_len()],
                    mac_algorithm,
                );
                for length in (0..=64).chain([683]) {
                    let plain = vec![0x5a; length];
                    let mut aad = [0; 13];
                    aad[8] = 23;
                    aad[9..11].copy_from_slice(&[3, 3]);
                    aad[11..].copy_from_slice(&(length as u16).to_be_bytes());
                    let record = cipher.encrypt(0, &aad, &plain).unwrap();
                    let expected = 16 + ((length + mac_algorithm.mac_len()) / 16 + 1) * 16;
                    assert_eq!(
                        record.len(),
                        expected,
                        "length={length}, MAC={mac_algorithm:?}"
                    );
                    assert_eq!(cipher.decrypt(&aad, &record).unwrap(), plain);
                }
            }
        }
    }

    #[test]
    fn cbc_accepts_valid_nonminimal_peer_padding() {
        let cipher = Tls12CbcCipher::new(&[0x42; 16], &[0x24; 20], CbcMacAlgorithm::HmacSha1);
        let plain = vec![0x5a; 16_384];
        let mut aad = [0; 13];
        aad[8] = 23;
        aad[9..11].copy_from_slice(&[3, 3]);
        aad[11..].copy_from_slice(&16384u16.to_be_bytes());
        let mut inner = plain.clone();
        inner.extend_from_slice(&cipher.compute_mac(&aad, &plain));
        inner.resize(inner.len() + 252, 251);
        let iv = [0x17; 16];
        let mut record = iv.to_vec();
        record.extend_from_slice(&cipher.cbc_encrypt(&iv, &mut inner).unwrap());
        assert_eq!(record.len(), 16_672);
        assert_eq!(cipher.decrypt(&aad, &record).unwrap(), plain);
    }

    #[test]
    fn test_cipher_suite_resolution() {
        assert!(Tls12CipherSuite::from_code_point(0xC02F).unwrap().is_aead());
        assert!(Tls12CipherSuite::from_code_point(0xC013).unwrap().is_cbc());
        assert!(Tls12CipherSuite::from_code_point(0xFFFF).is_none());
    }

    #[test]
    fn test_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let cipher = Tls12GcmCipher::new(&key, &iv, false).unwrap();

        // AAD: seq_num(8) || content_type(1) || version(2) || length(2)
        let aad = [0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x0F];
        let plaintext = b"Hello, TLS 1.2!";

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();
        // Should have 8-byte explicit nonce + ciphertext + 16-byte tag
        assert_eq!(ciphertext.len(), 8 + plaintext.len() + 16);

        let decrypted = cipher.decrypt(&aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0xAA; 32];
        let iv = [0xBB; 12];
        let cipher = Tls12Chacha20Cipher::new(&key, &iv).unwrap();

        let aad = [0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x10];
        let plaintext = b"ChaCha20 TLS 1.2";

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(1, &aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_aes128_sha1_roundtrip() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        // AAD: seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        let plaintext = b"Hello, TLS 1.2 CBC!";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,    // seq_num = 1
            0x17, // content_type = application_data
            0x03,
            0x03, // version = TLS 1.2
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();

        // Ciphertext: iv(16) + encrypted(plaintext + mac(20) + padding)
        assert!(ciphertext.len() >= 16 + 16); // at least IV + one block
        assert_eq!((ciphertext.len() - 16) % 16, 0); // encrypted part is block-aligned

        // For decryption, AAD carries the *record* payload length (ciphertext - iv = encrypted part)
        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_aes256_sha256_roundtrip() {
        let enc_key = [0x55u8; 32];
        let mac_key = [0xBB; 32];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha256);

        let plaintext = b"AES-256-CBC with HMAC-SHA256 test data that spans multiple blocks!!";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            5,
            0x17,
            0x03,
            0x03,
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let ciphertext = cipher.encrypt(5, &aad, plaintext).unwrap();
        assert_eq!((ciphertext.len() - 16) % 16, 0);

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            5,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_empty_plaintext() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        let plaintext = b"";
        let aad = [0, 0, 0, 0, 0, 0, 0, 0, 0x17, 0x03, 0x03, 0x00, 0x00];

        let ciphertext = cipher.encrypt(0, &aad, plaintext).unwrap();

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let decrypted = cipher.decrypt(&dec_aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext.as_ref());
    }

    #[test]
    fn test_cbc_tampered_ciphertext_fails() {
        let enc_key = [0x42u8; 16];
        let mac_key = [0xAA; 20];
        let cipher = Tls12CbcCipher::new(&enc_key, &mac_key, CbcMacAlgorithm::HmacSha1);

        let plaintext = b"tamper test";
        let pt_len = plaintext.len() as u16;
        let aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (pt_len >> 8) as u8,
            pt_len as u8,
        ];

        let mut ciphertext = cipher.encrypt(1, &aad, plaintext).unwrap();

        // Tamper with encrypted data (flip a bit after the IV)
        if ciphertext.len() > 20 {
            ciphertext[20] ^= 0x01;
        }

        let record_payload_len = (ciphertext.len() - 16) as u16;
        let dec_aad = [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x17,
            0x03,
            0x03,
            (record_payload_len >> 8) as u8,
            record_payload_len as u8,
        ];

        let result = cipher.decrypt(&dec_aad, &ciphertext);
        assert!(result.is_err());
    }
}
