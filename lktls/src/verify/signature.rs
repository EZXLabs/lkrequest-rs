//! Handshake signature semantics, distinct from certificate-chain signatures.

use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
};
use webpki::aws_lc_rs as algorithms;

use crate::crypto::suites::Authentication;

type Algorithms = &'static [&'static dyn SignatureVerificationAlgorithm];
const RSA_SHA256: Algorithms = &[algorithms::RSA_PKCS1_2048_8192_SHA256];
const RSA_SHA384: Algorithms = &[algorithms::RSA_PKCS1_2048_8192_SHA384];
const RSA_SHA512: Algorithms = &[algorithms::RSA_PKCS1_2048_8192_SHA512];
const PSS_SHA256: Algorithms = &[algorithms::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
const PSS_SHA384: Algorithms = &[algorithms::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
const PSS_SHA512: Algorithms = &[algorithms::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];
const ECDSA_SHA256: Algorithms = &[
    algorithms::ECDSA_P256_SHA256,
    algorithms::ECDSA_P384_SHA256,
    algorithms::ECDSA_P521_SHA256,
];
const ECDSA_SHA384: Algorithms = &[
    algorithms::ECDSA_P256_SHA384,
    algorithms::ECDSA_P384_SHA384,
    algorithms::ECDSA_P521_SHA384,
];
const ECDSA_SHA512: Algorithms = &[
    algorithms::ECDSA_P256_SHA512,
    algorithms::ECDSA_P384_SHA512,
    algorithms::ECDSA_P521_SHA512,
];
const P256_SHA256: Algorithms = &[algorithms::ECDSA_P256_SHA256];
const P384_SHA384: Algorithms = &[algorithms::ECDSA_P384_SHA384];
const P521_SHA512: Algorithms = &[algorithms::ECDSA_P521_SHA512];
const ED25519: Algorithms = &[algorithms::ED25519];

// Only handshake verification uses these legacy algorithms. Certificate-chain
// verification retains webpki's existing policy and TLS 1.3 never selects them.
#[derive(Debug)]
struct LegacySha1 {
    key_id: AlgorithmIdentifier,
    signature_id: AlgorithmIdentifier,
    algorithm: &'static dyn aws_lc_rs::signature::VerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for LegacySha1 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.key_id
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_id
    }
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        aws_lc_rs::signature::UnparsedPublicKey::new(self.algorithm, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }
}

const RSA_SHA1: Algorithms = &[&LegacySha1 {
    key_id: alg_id::RSA_ENCRYPTION,
    signature_id: AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0,
    ]),
    algorithm: &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
}];
const ECDSA_SHA1: Algorithms = &[
    &LegacySha1 {
        key_id: alg_id::ECDSA_P256,
        signature_id: AlgorithmIdentifier::from_slice(&[
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01,
        ]),
        algorithm: &aws_lc_rs::signature::ECDSA_P256_SHA1_ASN1,
    },
    &LegacySha1 {
        key_id: alg_id::ECDSA_P521,
        signature_id: AlgorithmIdentifier::from_slice(&[
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01,
        ]),
        algorithm: &aws_lc_rs::signature::ECDSA_P521_SHA1_ASN1,
    },
];

#[derive(Clone, Copy)]
pub(crate) enum SignaturePurpose {
    Tls12ServerKeyExchange,
    Tls13CertificateVerify,
}

pub(crate) fn tls12_authentication(scheme: u16) -> Option<Authentication> {
    match scheme {
        0x0201 | 0x0301 | 0x0401 | 0x0501 | 0x0601 | 0x0804..=0x0806 | 0x0809..=0x080b => {
            Some(Authentication::Rsa)
        }
        0x0203 | 0x0403 | 0x0503 | 0x0603 | 0x0807 | 0x0808 => Some(Authentication::Ecdsa),
        _ => None,
    }
}

fn algorithms(purpose: SignaturePurpose, scheme: u16) -> Option<Algorithms> {
    match (purpose, scheme) {
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0201) => Some(RSA_SHA1),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0203) => Some(ECDSA_SHA1),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0401) => Some(RSA_SHA256),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0501) => Some(RSA_SHA384),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0601) => Some(RSA_SHA512),
        (_, 0x0804) => Some(PSS_SHA256),
        (_, 0x0805) => Some(PSS_SHA384),
        (_, 0x0806) => Some(PSS_SHA512),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0403) => Some(ECDSA_SHA256),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0503) => Some(ECDSA_SHA384),
        (SignaturePurpose::Tls12ServerKeyExchange, 0x0603) => Some(ECDSA_SHA512),
        (SignaturePurpose::Tls13CertificateVerify, 0x0403) => Some(P256_SHA256),
        (SignaturePurpose::Tls13CertificateVerify, 0x0503) => Some(P384_SHA384),
        (SignaturePurpose::Tls13CertificateVerify, 0x0603) => Some(P521_SHA512),
        (_, 0x0807) => Some(ED25519),
        _ => None,
    }
}

pub(crate) fn supports(purpose: SignaturePurpose, scheme: u16) -> bool {
    algorithms(purpose, scheme).is_some()
}

pub(crate) fn verify(
    purpose: SignaturePurpose,
    scheme: u16,
    certificate: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let candidates = algorithms(purpose, scheme)
        .ok_or_else(|| format!("unsupported handshake signature algorithm: 0x{scheme:04x}"))?;
    let certificate = CertificateDer::from(certificate);
    let certificate = webpki::EndEntityCert::try_from(&certificate)
        .map_err(|error| format!("invalid signing certificate: {error}"))?;
    // webpki checks the SPKI algorithm/curve for each candidate. TLS 1.2
    // identifies the signature and hash, so more than one curve can apply.
    for algorithm in candidates {
        if certificate
            .verify_signature(*algorithm, message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(format!(
        "handshake signature verification failed for 0x{scheme:04x}"
    ))
}
