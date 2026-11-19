//! Implementation-backed suite descriptions, resolved during negotiation.

use super::aead::AeadAlgorithm;
use super::hkdf::HkdfAlgorithm;
use super::prf::PrfAlgorithm;
use super::tls12_cipher::{
    CbcMacAlgorithm, CbcMacMode, Tls12CbcCipher, Tls12Chacha20Cipher, Tls12CipherSuite,
    Tls12GcmCipher, Tls12KeyExchange, Tls12RecordCipher,
};
use crate::error::{Result, TlsError};

/// Per-key TLS record budgets; QUIC packet limits are a separate contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TlsRecordLimits {
    pub(crate) encrypt: u64,
    pub(crate) decrypt: u64,
}

impl TlsRecordLimits {
    /// Conservative AES-GCM confidentiality bound for maximum-sized TLS
    /// records, matching rustls 0.23's 2^24-record bound (AEBounds Table 1).
    /// A peer's excess encryption has already spent its confidentiality budget;
    /// refusing to decrypt at that bound cannot undo it. As in rustls, reads
    /// enforce sequence exhaustion instead. Authentication failure is terminal,
    /// so TLS has no reusable QUIC-style failed-authentication budget.
    pub(crate) const AES_GCM: Self = Self {
        encrypt: 1 << 24,
        decrypt: u64::MAX,
    };

    /// ChaCha20-Poly1305 is bounded by the TLS sequence space. CBC currently
    /// receives only this sequence guard, not a claimed confidentiality bound
    /// or a mitigation for its known MAC-then-encrypt timing limitation.
    /// The final u64 sequence value is reserved to avoid counter wraparound.
    pub(crate) const SEQUENCE_ONLY: Self = Self {
        encrypt: u64::MAX,
        decrypt: u64::MAX,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authentication {
    Rsa,
    Ecdsa,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Tls12Protection {
    AesGcm {
        key_len: usize,
    },
    Chacha20Poly1305,
    AesCbc {
        key_len: usize,
        mac: CbcMacAlgorithm,
    },
    TripleDesCbc,
}

impl Tls12Protection {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::AesGcm { key_len } | Self::AesCbc { key_len, .. } => key_len,
            Self::Chacha20Poly1305 => 32,
            Self::TripleDesCbc => 24,
        }
    }

    pub(crate) fn mac_len(self) -> usize {
        match self {
            Self::AesCbc { mac, .. } => mac.mac_len(),
            Self::TripleDesCbc => 20,
            _ => 0,
        }
    }

    pub(crate) fn fixed_iv_len(self) -> usize {
        match self {
            Self::AesGcm { .. } => 4,
            Self::Chacha20Poly1305 => 12,
            // Preserve the legacy public key-block layout during migration.
            Self::AesCbc { .. } => 16,
            Self::TripleDesCbc => 8,
        }
    }

    pub(crate) fn aead(self) -> Option<AeadAlgorithm> {
        match self {
            Self::AesGcm { key_len: 16 } => Some(AeadAlgorithm::Aes128Gcm),
            Self::AesGcm { .. } => Some(AeadAlgorithm::Aes256Gcm),
            Self::Chacha20Poly1305 => Some(AeadAlgorithm::Chacha20Poly1305),
            Self::AesCbc { .. } | Self::TripleDesCbc => None,
        }
    }
}

pub(crate) struct Tls12Suite {
    pub(crate) code: u16,
    pub(crate) key_exchange: Tls12KeyExchange,
    pub(crate) authentication: Authentication,
    pub(crate) prf: PrfAlgorithm,
    pub(crate) protection: Tls12Protection,
}

impl Tls12Suite {
    pub(crate) fn hash(&self) -> HkdfAlgorithm {
        match self.prf {
            PrfAlgorithm::Sha256 => HkdfAlgorithm::Sha256,
            PrfAlgorithm::Sha384 => HkdfAlgorithm::Sha384,
        }
    }

    pub(crate) fn record_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
    ) -> Result<Tls12RecordCipher> {
        self.record_cipher_with_mode(key, iv, mac_key, CbcMacMode::MacThenEncrypt)
    }

    pub(crate) fn record_cipher_with_mode(
        &self,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
        mac_mode: CbcMacMode,
    ) -> Result<Tls12RecordCipher> {
        if mac_mode == CbcMacMode::EncryptThenMac
            && !matches!(
                self.protection,
                Tls12Protection::AesCbc { .. } | Tls12Protection::TripleDesCbc
            )
        {
            return Err(TlsError::CryptoError(
                "Encrypt-then-MAC requires CBC protection".into(),
            ));
        }
        for (name, actual, required) in [
            ("key", key.len(), self.protection.key_len()),
            ("IV", iv.len(), self.protection.fixed_iv_len()),
            ("MAC key", mac_key.len(), self.protection.mac_len()),
        ] {
            if actual != required {
                return Err(TlsError::CryptoError(format!(
                    "TLS 1.2 suite 0x{:04x} requires {required} {name} bytes, got {actual}",
                    self.code
                )));
            }
        }
        match self.protection {
            Tls12Protection::AesGcm { key_len } => Ok(Tls12RecordCipher::Gcm(Tls12GcmCipher::new(
                key,
                iv.try_into().unwrap(),
                key_len == 32,
            )?)),
            Tls12Protection::Chacha20Poly1305 => Ok(Tls12RecordCipher::Chacha20(
                Tls12Chacha20Cipher::new(key.try_into().unwrap(), iv.try_into().unwrap())?,
            )),
            Tls12Protection::AesCbc { mac, .. } => Ok(Tls12RecordCipher::Cbc(
                Tls12CbcCipher::new_with_mode(key, mac_key, mac, mac_mode),
            )),
            Tls12Protection::TripleDesCbc => Ok(Tls12RecordCipher::Cbc(
                Tls12CbcCipher::new_with_mode(key, mac_key, CbcMacAlgorithm::HmacSha1, mac_mode),
            )),
        }
    }
}

// Generate both directions from one inventory while preserving the public enum.
macro_rules! tls12_suites {
    ($( $variant:ident => ($code:literal, $kx:ident, $auth:ident, $prf:ident, $protection:expr) ),+ $(,)?) => {
        pub(crate) fn tls12_suite(code: u16) -> Option<Tls12CipherSuite> {
            match code {
                $( $code => Some(Tls12CipherSuite::$variant), )+
                _ => None,
            }
        }

        pub(crate) fn tls12_descriptor(suite: Tls12CipherSuite) -> &'static Tls12Suite {
            match suite {
                $( Tls12CipherSuite::$variant => &Tls12Suite {
                    code: $code,
                    key_exchange: Tls12KeyExchange::$kx,
                    authentication: Authentication::$auth,
                    prf: PrfAlgorithm::$prf,
                    protection: $protection,
                }, )+
            }
        }
    };
}

use CbcMacAlgorithm::{HmacSha1, HmacSha256, HmacSha384};
use Tls12Protection::{AesCbc, AesGcm, Chacha20Poly1305, TripleDesCbc};

tls12_suites! {
    RsaTripleDesCbcSha => (0x000a, Rsa, Rsa, Sha256, TripleDesCbc),
    EcdheEcdsaTripleDesCbcSha => (0xc008, Ecdhe, Ecdsa, Sha256, TripleDesCbc),
    EcdheRsaTripleDesCbcSha => (0xc012, Ecdhe, Rsa, Sha256, TripleDesCbc),
    EcdheEcdsaAes128GcmSha256 => (0xc02b, Ecdhe, Ecdsa, Sha256, AesGcm { key_len: 16 }),
    EcdheRsaAes128GcmSha256 => (0xc02f, Ecdhe, Rsa, Sha256, AesGcm { key_len: 16 }),
    EcdheEcdsaAes256GcmSha384 => (0xc02c, Ecdhe, Ecdsa, Sha384, AesGcm { key_len: 32 }),
    EcdheRsaAes256GcmSha384 => (0xc030, Ecdhe, Rsa, Sha384, AesGcm { key_len: 32 }),
    EcdheEcdsaChacha20Poly1305 => (0xcca9, Ecdhe, Ecdsa, Sha256, Chacha20Poly1305),
    EcdheRsaChacha20Poly1305 => (0xcca8, Ecdhe, Rsa, Sha256, Chacha20Poly1305),
    EcdheEcdsaAes128CbcSha => (0xc009, Ecdhe, Ecdsa, Sha256, AesCbc { key_len: 16, mac: HmacSha1 }),
    EcdheEcdsaAes256CbcSha => (0xc00a, Ecdhe, Ecdsa, Sha256, AesCbc { key_len: 32, mac: HmacSha1 }),
    EcdheEcdsaAes128CbcSha256 => (0xc023, Ecdhe, Ecdsa, Sha256, AesCbc { key_len: 16, mac: HmacSha256 }),
    EcdheEcdsaAes256CbcSha384 => (0xc024, Ecdhe, Ecdsa, Sha384, AesCbc { key_len: 32, mac: HmacSha384 }),
    EcdheRsaAes128CbcSha => (0xc013, Ecdhe, Rsa, Sha256, AesCbc { key_len: 16, mac: HmacSha1 }),
    EcdheRsaAes256CbcSha => (0xc014, Ecdhe, Rsa, Sha256, AesCbc { key_len: 32, mac: HmacSha1 }),
    EcdheRsaAes128CbcSha256 => (0xc027, Ecdhe, Rsa, Sha256, AesCbc { key_len: 16, mac: HmacSha256 }),
    EcdheRsaAes256CbcSha384 => (0xc028, Ecdhe, Rsa, Sha384, AesCbc { key_len: 32, mac: HmacSha384 }),
    RsaAes256CbcSha => (0x0035, Rsa, Rsa, Sha256, AesCbc { key_len: 32, mac: HmacSha1 }),
    RsaAes128CbcSha => (0x002f, Rsa, Rsa, Sha256, AesCbc { key_len: 16, mac: HmacSha1 }),
    RsaAes256CbcSha256 => (0x003d, Rsa, Rsa, Sha256, AesCbc { key_len: 32, mac: HmacSha256 }),
    RsaAes128CbcSha256 => (0x003c, Rsa, Rsa, Sha256, AesCbc { key_len: 16, mac: HmacSha256 }),
    RsaAes128GcmSha256 => (0x009c, Rsa, Rsa, Sha256, AesGcm { key_len: 16 }),
    RsaAes256GcmSha384 => (0x009d, Rsa, Rsa, Sha384, AesGcm { key_len: 32 }),
}

pub(crate) struct Tls13Suite {
    pub(crate) hash: HkdfAlgorithm,
    pub(crate) aead: AeadAlgorithm,
}

pub(crate) fn tls13_suite(code: u16) -> Option<&'static Tls13Suite> {
    match code {
        0x1301 => Some(&Tls13Suite {
            hash: HkdfAlgorithm::Sha256,
            aead: AeadAlgorithm::Aes128Gcm,
        }),
        0x1302 => Some(&Tls13Suite {
            hash: HkdfAlgorithm::Sha384,
            aead: AeadAlgorithm::Aes256Gcm,
        }),
        0x1303 => Some(&Tls13Suite {
            hash: HkdfAlgorithm::Sha256,
            aead: AeadAlgorithm::Chacha20Poly1305,
        }),
        _ => None,
    }
}
