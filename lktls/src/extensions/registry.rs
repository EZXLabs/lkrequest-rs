//! Built-in extension ownership. Raw encoders do not replace these parsers.

use super::tls12::ServerValue;
use crate::error::{AlertDescription, Result, TlsError};
use crate::profile::types::ext_type;

type Tls12Parser = for<'a> fn(&'a [u8]) -> Result<ServerValue<'a>>;
type ClientValidator = fn(&[u8]) -> Result<()>;

#[derive(Clone, Copy)]
pub(crate) enum ServerContext {
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    CertificateEntry,
    CertificateRequest,
    NewSessionTicket,
}

impl ServerContext {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

const SH: u8 = ServerContext::ServerHello.bit();
const HRR: u8 = ServerContext::HelloRetryRequest.bit();
const EE: u8 = ServerContext::EncryptedExtensions.bit();
const CE: u8 = ServerContext::CertificateEntry.bit();
const CR: u8 = ServerContext::CertificateRequest.bit();
const NST: u8 = ServerContext::NewSessionTicket.bit();

struct Descriptor {
    code: u16,
    tls12_server: Option<Tls12Parser>,
    client_validator: Option<ClientValidator>,
    tls13_contexts: u8,
}

macro_rules! extensions {
    ($( $code:ident => ($parser:expr, $client:expr, $contexts:expr) ),+ $(,)?) => {
        const BUILT_INS: &[Descriptor] = &[
            $(Descriptor { code: ext_type::$code, tls12_server: $parser, client_validator: $client, tls13_contexts: $contexts },)+
        ];
    };
}

pub(crate) fn validate_client_payload(code: u16, data: &[u8]) -> Result<()> {
    if let Some(validate) = BUILT_INS
        .iter()
        .find(|entry| entry.code == code)
        .and_then(|entry| entry.client_validator)
    {
        validate(data)?;
    }
    Ok(())
}

extensions! {
    SNI => (Some(super::sni::parse_tls12_server), None, EE),
    STATUS_REQUEST => (Some(super::status_request::parse_tls12_server), None, CE | CR),
    SUPPORTED_GROUPS => (None, Some(super::supported_groups::validate_payload), EE),
    EC_POINT_FORMATS => (Some(super::ec_point_formats::parse_tls12_server), None, 0),
    SIGNATURE_ALGORITHMS => (None, None, CR),
    ALPN => (Some(super::alpn::parse_tls12_server), None, EE),
    SIGNED_CERTIFICATE_TIMESTAMP => (Some(super::sct::parse_tls12_server), Some(super::sct::validate_client_payload), CE | CR),
    PADDING => (None, None, 0),
    ENCRYPT_THEN_MAC => (Some(super::encrypt_then_mac::parse_tls12_server), Some(super::encrypt_then_mac::validate_payload), 0),
    EXTENDED_MASTER_SECRET => (Some(super::extended_master_secret::parse_tls12_server), Some(super::extended_master_secret::validate_payload), 0),
    COMPRESS_CERTIFICATE => (None, None, CR),
    RECORD_SIZE_LIMIT => (Some(super::record_size_limit::parse_tls12_server), None, EE),
    DELEGATED_CREDENTIALS => (None, None, CE | CR),
    SESSION_TICKET => (Some(super::session_ticket::parse_tls12_server), None, 0),
    PRE_SHARED_KEY => (None, None, SH),
    EARLY_DATA => (None, None, EE | NST),
    SUPPORTED_VERSIONS => (None, None, SH | HRR),
    COOKIE => (None, None, HRR),
    PSK_KEY_EXCHANGE_MODES => (None, None, 0),
    KEY_SHARE => (None, None, SH | HRR),
    QUIC_TRANSPORT_PARAMETERS => (None, None, EE),
    APPLICATION_SETTINGS => (None, None, EE),
    APPLICATION_SETTINGS_NEW => (None, None, EE),
    TRUST_ANCHOR_IDS => (None, None, EE | CE),
    ENCRYPTED_CLIENT_HELLO => (None, None, HRR | EE),
    RENEGOTIATION_INFO => (Some(super::renegotiation_info::parse_tls12_server), None, 0),
}

pub(crate) fn check_server_context(
    code: u16,
    context: ServerContext,
    offered: Option<&[u16]>,
) -> Result<()> {
    let descriptor = BUILT_INS.iter().find(|entry| entry.code == code);
    let allowed = descriptor.is_none_or(|entry| entry.tls13_contexts & context.bit() != 0);
    let offer_required = !matches!(
        context,
        ServerContext::CertificateRequest | ServerContext::NewSessionTicket
    ) && !(matches!(context, ServerContext::HelloRetryRequest)
        && code == ext_type::COOKIE);
    if (offer_required && crate::handshake::client_hello_wire::is_grease(code))
        || !allowed
        || offer_required && offered.is_some_and(|offers| !offers.contains(&code))
    {
        return Err(TlsError::local_alert(AlertDescription::UnsupportedExtension, format!("extension 0x{code:04x} is not permitted or was not offered for this TLS 1.3 message")));
    }
    // Unknown extensions are tolerated in extensible blocks, but SH/HRR have
    // a closed set because their contents establish cryptographic parameters.
    if descriptor.is_none()
        && matches!(
            context,
            ServerContext::ServerHello | ServerContext::HelloRetryRequest
        )
    {
        return Err(TlsError::local_alert(
            AlertDescription::UnsupportedExtension,
            "unknown ServerHello extension",
        ));
    }
    Ok(())
}

pub(super) fn parse_tls12_server(code: u16, data: &[u8]) -> Result<ServerValue<'_>> {
    if crate::handshake::client_hello_wire::is_grease(code) {
        return Err(TlsError::local_alert(
            AlertDescription::UnsupportedExtension,
            "server echoed a GREASE extension",
        ));
    }
    match BUILT_INS.iter().find(|descriptor| descriptor.code == code) {
        Some(Descriptor {
            tls12_server: Some(parse),
            ..
        }) => parse(data),
        Some(_) => Err(TlsError::local_alert(
            AlertDescription::UnsupportedExtension,
            format!("extension 0x{code:04x} is not permitted in TLS 1.2 ServerHello"),
        )),
        None => Ok(ServerValue::Ignored),
    }
}

pub(super) fn require_empty(data: &[u8]) -> Result<()> {
    if !data.is_empty() {
        return Err(TlsError::local_alert(
            AlertDescription::DecodeError,
            "server extension must have an empty payload",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_is_ignored_in_unsolicited_server_advertisement_contexts() {
        assert!(check_server_context(0x1a1a, ServerContext::CertificateRequest, Some(&[])).is_ok());
        assert!(check_server_context(0x1a1a, ServerContext::NewSessionTicket, Some(&[])).is_ok());
        assert!(
            check_server_context(0x1a1a, ServerContext::EncryptedExtensions, Some(&[0x1a1a]))
                .is_err()
        );
    }

    #[test]
    fn built_in_code_points_have_one_owner() {
        let mut codes = std::collections::HashSet::new();
        assert!(super::BUILT_INS
            .iter()
            .all(|entry| codes.insert(entry.code)));
    }
}
