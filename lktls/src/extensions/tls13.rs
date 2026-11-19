//! Typed TLS 1.3 extension results, without handshake or key-schedule ownership.

use super::registry::{check_server_context, ServerContext};
use crate::error::{AlertDescription, Result, TlsError};
use crate::profile::types::{ext_type, TlsClientHelloStyle};
use crate::wire::{decode_error, Reader};

/// Decode the body of a handshake CertificateRequest. Post-handshake client
/// authentication is not supported, so the request context must be empty.
pub(crate) fn parse_certificate_request(payload: &[u8]) -> Result<Vec<u8>> {
    let mut input = Reader::new(payload);
    let context = input.vector8()?;
    if !context.is_empty() {
        return Err(TlsError::local_alert(
            AlertDescription::IllegalParameter,
            "handshake CertificateRequest context must be empty",
        ));
    }
    let extension_bytes = input.vector16()?;
    input.finish()?;
    if extension_bytes.is_empty() {
        return Err(decode_error("empty CertificateRequest extension list"));
    }

    let mut extensions = Reader::new(extension_bytes);
    let mut seen = std::collections::HashSet::new();
    let mut has_signature_algorithms = false;
    while !extensions.is_empty() {
        let code = extensions.u16()?;
        let body = extensions.vector16()?;
        if !seen.insert(code) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!("duplicate CertificateRequest extension 0x{code:04x}"),
            ));
        }
        check_server_context(code, ServerContext::CertificateRequest, None)?;
        if code == ext_type::SIGNATURE_ALGORITHMS {
            super::signature_algorithms::validate_payload(body)?;
            has_signature_algorithms = true;
        } else {
            super::registry::validate_client_payload(code, body)?;
        }
    }
    if !has_signature_algorithms {
        return Err(TlsError::local_alert(
            AlertDescription::MissingExtension,
            "CertificateRequest is missing signature_algorithms",
        ));
    }
    Ok(context.to_vec())
}

pub(crate) enum ServerValue<'a> {
    Ignored,
    ServerName,
    SupportedGroups,
    Alpn(&'a [u8]),
    Alps { code: u16, payload: &'a [u8] },
    EchRetryConfigs(&'a [u8]),
    EarlyData,
    RecordSizeLimit(u16),
    QuicParameters(super::quic_transport_params::QuicTransportParams),
    TrustAnchors(Vec<crate::trust_anchor::TrustAnchorId>),
}

pub(crate) fn parse_encrypted_extension<'a>(
    code: u16,
    payload: &'a [u8],
    offered: Option<&[u16]>,
    style: TlsClientHelloStyle,
    psk_accepted: bool,
) -> Result<ServerValue<'a>> {
    check_server_context(code, ServerContext::EncryptedExtensions, offered)?;
    match code {
        ext_type::SNI => {
            super::registry::require_empty(payload)?;
            Ok(ServerValue::ServerName)
        }
        ext_type::SUPPORTED_GROUPS => {
            super::supported_groups::validate_payload(payload)?;
            Ok(ServerValue::SupportedGroups)
        }
        ext_type::ALPN => super::alpn::parse_server_alpn_bytes(payload)
            .map(ServerValue::Alpn)
            .ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::DecodeError,
                    "invalid server ALPN protocol list",
                )
            }),
        ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW => {
            Ok(ServerValue::Alps { code, payload })
        }
        ext_type::ENCRYPTED_CLIENT_HELLO => Ok(ServerValue::EchRetryConfigs(payload)),
        ext_type::EARLY_DATA => {
            let nss = style == TlsClientHelloStyle::FirefoxNss;
            if !payload.is_empty() {
                return Err(TlsError::local_alert(
                    if nss {
                        AlertDescription::HandshakeFailure
                    } else {
                        AlertDescription::DecodeError
                    },
                    "server early_data extension must be empty",
                ));
            }
            if !psk_accepted {
                return Err(TlsError::local_alert(
                    if nss {
                        AlertDescription::IllegalParameter
                    } else {
                        AlertDescription::UnsupportedExtension
                    },
                    "server accepted early_data without resuming the offered PSK",
                ));
            }
            Ok(ServerValue::EarlyData)
        }
        ext_type::RECORD_SIZE_LIMIT => {
            super::record_size_limit::parse_peer_record_size_limit(payload)
                .map(ServerValue::RecordSizeLimit)
        }
        ext_type::QUIC_TRANSPORT_PARAMETERS => {
            super::quic_transport_params::decode_transport_params(payload)
                .map(ServerValue::QuicParameters)
        }
        ext_type::TRUST_ANCHOR_IDS => {
            crate::trust_anchor::decode_list(payload, false).map(ServerValue::TrustAnchors)
        }
        _ => Ok(ServerValue::Ignored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_request(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![0, 0, 0];
        for (code, payload) in extensions {
            body.extend_from_slice(&code.to_be_bytes());
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
        }
        let length = (body.len() - 3) as u16;
        body[1..3].copy_from_slice(&length.to_be_bytes());
        body
    }

    fn request_alert(body: &[u8], expected: AlertDescription) {
        assert!(
            matches!(parse_certificate_request(body), Err(TlsError::LocalAlert { alert, .. }) if alert.description == expected),
            "unexpected result for {body:?}"
        );
    }

    #[test]
    fn certificate_request_requires_empty_context_and_exact_framing() {
        let valid = certificate_request(&[(ext_type::SIGNATURE_ALGORITHMS, &[0, 2, 4, 3])]);
        assert_eq!(parse_certificate_request(&valid).unwrap(), Vec::<u8>::new());
        for length in 0..valid.len() {
            request_alert(&valid[..length], AlertDescription::DecodeError);
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        request_alert(&trailing, AlertDescription::DecodeError);
        let mut nonempty_context = vec![1, 42];
        nonempty_context.extend_from_slice(&valid[1..]);
        request_alert(&nonempty_context, AlertDescription::IllegalParameter);
        request_alert(&[0, 0, 0], AlertDescription::DecodeError);
        for malformed_extension in [&[0][..], &[0, 13], &[0, 13, 0], &[0, 13, 0, 1]] {
            let mut body = vec![0, 0, malformed_extension.len() as u8];
            body.extend_from_slice(malformed_extension);
            request_alert(&body, AlertDescription::DecodeError);
        }
    }

    #[test]
    fn certificate_request_requires_a_complete_signature_scheme_list() {
        for malformed in [
            &[][..],
            &[0],
            &[0, 0],
            &[0, 1, 4],
            &[0, 2, 4],
            &[0, 2, 4, 3, 0],
            &[0, 4, 4, 3],
        ] {
            request_alert(
                &certificate_request(&[(ext_type::SIGNATURE_ALGORITHMS, malformed)]),
                AlertDescription::DecodeError,
            );
        }
        request_alert(
            &certificate_request(&[(0xff01, &[0])]),
            AlertDescription::UnsupportedExtension,
        );
        request_alert(
            &certificate_request(&[(0xeeff, &[])]),
            AlertDescription::MissingExtension,
        );
        assert!(parse_certificate_request(&certificate_request(&[(
            ext_type::SIGNATURE_ALGORITHMS,
            &[0, 4, 0x1a, 0x1a, 0xfe, 0xff],
        )]))
        .is_ok());
    }

    #[test]
    fn certificate_request_rejects_duplicate_and_forbidden_extensions() {
        assert!(parse_certificate_request(&certificate_request(&[(
            ext_type::SIGNATURE_ALGORITHMS,
            &[0, 2, 4, 3]
        )]))
        .is_ok());
        for code in [ext_type::SIGNATURE_ALGORITHMS, 0xeeff, 0x1a1a] {
            let payload = &[0, 2, 4, 3];
            request_alert(
                &certificate_request(&[(code, payload), (code, payload)]),
                AlertDescription::IllegalParameter,
            );
        }
        for code in [
            ext_type::ALPN,
            ext_type::KEY_SHARE,
            ext_type::SUPPORTED_VERSIONS,
            ext_type::SUPPORTED_GROUPS,
            ext_type::EARLY_DATA,
            ext_type::QUIC_TRANSPORT_PARAMETERS,
        ] {
            request_alert(
                &certificate_request(&[
                    (ext_type::SIGNATURE_ALGORITHMS, &[0, 2, 4, 3]),
                    (code, &[]),
                ]),
                AlertDescription::UnsupportedExtension,
            );
        }
    }

    #[test]
    fn certificate_request_ignores_unknown_and_validates_owned_optional_bodies() {
        let sigalgs = (ext_type::SIGNATURE_ALGORITHMS, &[0, 2, 4, 3][..]);
        assert!(parse_certificate_request(&certificate_request(&[
            sigalgs,
            (0xeeff, &[1, 2, 3]),
            (0x1a1a, &[42]),
            (ext_type::SIGNED_CERTIFICATE_TIMESTAMP, &[]),
        ]))
        .is_ok());
        request_alert(
            &certificate_request(&[sigalgs, (ext_type::SIGNED_CERTIFICATE_TIMESTAMP, &[0])]),
            AlertDescription::DecodeError,
        );
    }

    #[test]
    fn context_and_offer_rejection_precede_payload_parsing() {
        for code in [
            ext_type::KEY_SHARE,
            ext_type::SUPPORTED_VERSIONS,
            ext_type::STATUS_REQUEST,
            ext_type::SESSION_TICKET,
            ext_type::EXTENDED_MASTER_SECRET,
            0x1a1a,
        ] {
            assert!(
                matches!(parse_encrypted_extension(code, &[], Some(&[code]), TlsClientHelloStyle::Generic, false), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::UnsupportedExtension)
            );
        }
        assert!(parse_encrypted_extension(
            0xeeff,
            &[1],
            Some(&[0xeeff]),
            TlsClientHelloStyle::Generic,
            false
        )
        .is_ok());
        assert!(
            matches!(parse_encrypted_extension(ext_type::ALPN, &[], Some(&[]), TlsClientHelloStyle::Generic, false), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::UnsupportedExtension)
        );
    }

    #[test]
    fn empty_ack_and_group_vectors_are_checked() {
        assert!(parse_encrypted_extension(
            0,
            &[1],
            Some(&[0]),
            TlsClientHelloStyle::Generic,
            false
        )
        .is_err());
        for invalid in [&[][..], &[0, 0], &[0, 1, 0], &[0, 2, 0, 29, 0]] {
            assert!(parse_encrypted_extension(
                10,
                invalid,
                Some(&[10]),
                TlsClientHelloStyle::Generic,
                false
            )
            .is_err());
        }
        assert!(matches!(
            parse_encrypted_extension(
                10,
                &[0, 2, 0, 29],
                Some(&[10]),
                TlsClientHelloStyle::Generic,
                false
            )
            .unwrap(),
            ServerValue::SupportedGroups
        ));
    }
}
