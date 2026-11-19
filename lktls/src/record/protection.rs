//! Direction-specific ownership of record keys. Each value owns one backend key.

use super::Tls12RecordCipher;
use crate::crypto::aead::{Aead, AeadAlgorithm};
use crate::error::Result;

pub(crate) enum Protection {
    Tls13(Aead),
    Tls12(Tls12RecordCipher),
}

pub struct ReadKeys(pub(crate) Protection);
pub struct WriteKeys(pub(crate) Protection);

macro_rules! key_constructors {
    ($kind:ident) => {
        impl $kind {
            pub fn tls13(algorithm: AeadAlgorithm, key: &[u8], iv: &[u8]) -> Result<Self> {
                Aead::new(algorithm, key, iv).map(|key| Self(Protection::Tls13(key)))
            }
            pub fn tls12(cipher: Tls12RecordCipher) -> Self {
                Self(Protection::Tls12(cipher))
            }
        }
        impl From<Aead> for $kind {
            fn from(key: Aead) -> Self {
                Self(Protection::Tls13(key))
            }
        }
    };
}
key_constructors!(ReadKeys);
key_constructors!(WriteKeys);
