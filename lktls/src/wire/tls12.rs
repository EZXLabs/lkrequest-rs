//! Borrowed, exact TLS 1.2 handshake bodies (RFC 5246 and RFC 8422).

use super::{decode_error, Reader};
use crate::error::{AlertDescription, Result, TlsError};

pub(crate) fn certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut message = Reader::new(body);
    let mut certificates = Reader::new(message.vector24()?);
    message.finish()?;
    let mut result = Vec::new();
    while !certificates.is_empty() {
        let certificate = certificates.vector24()?;
        if certificate.is_empty() {
            return Err(decode_error("empty certificate entry"));
        }
        result.push(certificate.to_vec());
    }
    if result.is_empty() {
        return Err(TlsError::CertificateError(
            "server sent no certificates".into(),
        ));
    }
    Ok(result)
}

pub(crate) struct EcdheServerKeyExchange<'a> {
    pub(crate) group: u16,
    pub(crate) public_key: &'a [u8],
    pub(crate) signature_algorithm: u16,
    pub(crate) signature: &'a [u8],
    pub(crate) signed_params: &'a [u8],
}

impl<'a> EcdheServerKeyExchange<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self> {
        let mut input = Reader::new(body);
        if input.u8()? != 3 {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "ServerKeyExchange requires a named curve",
            ));
        }
        let group = input.u16()?;
        let public_key = input.vector8()?;
        if public_key.is_empty() {
            return Err(decode_error("empty ECDHE public key"));
        }
        let signed_params = &body[..4 + public_key.len()];
        let signature_algorithm = input.u16()?;
        let signature = input.vector16()?;
        if signature.is_empty() {
            return Err(decode_error("empty ServerKeyExchange signature"));
        }
        input.finish()?;
        Ok(Self {
            group,
            public_key,
            signature_algorithm,
            signature,
            signed_params,
        })
    }
}

pub(crate) fn certificate_request(body: &[u8]) -> Result<()> {
    let mut input = Reader::new(body);
    if input.vector8()?.is_empty() {
        return Err(decode_error("empty certificate types"));
    }
    let signatures = input.vector16()?;
    if signatures.is_empty() || !signatures.len().is_multiple_of(2) {
        return Err(decode_error(
            "invalid CertificateRequest signature algorithms",
        ));
    }
    let mut authorities = Reader::new(input.vector16()?);
    input.finish()?;
    while !authorities.is_empty() {
        if authorities.vector16()?.is_empty() {
            return Err(decode_error("empty CertificateRequest distinguished name"));
        }
    }
    Ok(())
}
