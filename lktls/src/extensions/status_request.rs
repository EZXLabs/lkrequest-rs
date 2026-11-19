//! Status Request (OCSP Stapling) extension — type 0x0005.
//!
//! Indicates that the client supports OCSP stapling.  The ClientHello
//! payload is a `CertificateStatusRequest` structure with:
//! - status_type = ocsp (1)
//! - responder_id_list length = 0
//! - request_extensions length = 0

use super::Extension;

pub(super) fn parse_tls12_server(
    data: &[u8],
) -> crate::error::Result<super::tls12::ServerValue<'_>> {
    super::registry::require_empty(data)?;
    Ok(super::tls12::ServerValue::StatusRequest)
}

pub(crate) fn parse_certificate_status(body: &[u8]) -> crate::error::Result<&[u8]> {
    let mut input = crate::wire::Reader::new(body);
    if input.u8()? != 1 {
        return Err(crate::error::TlsError::local_alert(
            crate::error::AlertDescription::IllegalParameter,
            "CertificateStatus must contain an OCSP response",
        ));
    }
    let response = input.vector24()?;
    if response.is_empty() {
        return Err(crate::wire::decode_error("empty OCSP response"));
    }
    input.finish()?;
    Ok(response)
}

/// Status Request (OCSP Stapling) extension.
///
/// This extension tells the server that the client supports receiving
/// an OCSP response stapled to the certificate.
pub struct StatusRequest;

impl Extension for StatusRequest {
    fn extension_type(&self) -> u16 {
        0x0005
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        // CertificateStatusRequest:
        //   status_type = ocsp (1)          — 1 byte
        //   responder_id_list length = 0    — 2 bytes
        //   request_extensions length = 0   — 2 bytes
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_status_request() {
        let ext = StatusRequest;
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
    }
}
