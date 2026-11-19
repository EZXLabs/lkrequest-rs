use bytes::Buf;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};
use crate::error::{AlertDescription, Result, TlsError};

use super::{AlpsSessionState, SessionTicketData, TicketTlsVersion};

pub(crate) struct Tls12Ticket {
    lifetime: u32,
    ticket: Vec<u8>,
}

impl Tls12Ticket {
    pub(crate) fn session_id_only() -> Self {
        Self {
            lifetime: 0,
            ticket: Vec::new(),
        }
    }

    pub(crate) fn parse_legacy_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() > 4 && payload[0] == 4 {
            let mut message = payload;
            message.try_get_u8().map_err(|_| decode_error())?;
            let length = message.try_get_uint(3).map_err(|_| decode_error())?;
            if length != message.remaining() as u64 {
                return Err(decode_error());
            }
            Self::parse_body(message)
        } else {
            Self::parse_body(payload)
        }
    }

    pub(crate) fn parse_body(mut body: &[u8]) -> Result<Self> {
        let lifetime = body.try_get_u32().map_err(|_| decode_error())?;
        let length = body.try_get_u16().map_err(|_| decode_error())? as usize;
        if length != body.remaining() {
            return Err(decode_error());
        }
        // RFC 5077 permits an empty ticket when the server cannot issue one.
        Ok(Self {
            lifetime,
            ticket: body.to_vec(),
        })
    }

    pub(crate) fn into_session(
        self,
        master_secret: &[u8],
        alpn: Option<String>,
        suite: Option<crate::crypto::tls12_cipher::Tls12CipherSuite>,
        used_extended_master_secret: Option<bool>,
    ) -> SessionTicketData {
        let (cipher_suite, hkdf_algorithm, aead_algorithm) = match suite {
            Some(suite) => {
                let descriptor = suite.descriptor();
                // Only the compatibility representation needs an AEAD for CBC.
                (
                    descriptor.code,
                    descriptor.hash(),
                    descriptor
                        .protection
                        .aead()
                        .unwrap_or(AeadAlgorithm::Aes128Gcm),
                )
            }
            None => (0, HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm),
        };
        SessionTicketData {
            ticket: self.ticket,
            resumption_psk: Vec::new(),
            tls_version: TicketTlsVersion::Tls12,
            used_extended_master_secret,
            cipher_suite,
            lifetime_secs: self.lifetime,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn,
            alps: AlpsSessionState::NotNegotiated,
            hkdf_algorithm,
            aead_algorithm,
            master_secret: master_secret.to_vec(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
        }
    }
}

pub(crate) struct Tls13Ticket<'a> {
    pub(crate) lifetime: u32,
    age_add: u32,
    nonce: &'a [u8],
    ticket: &'a [u8],
    pub(crate) early_data: Option<u32>,
}

fn decode_error() -> TlsError {
    TlsError::local_alert(
        AlertDescription::DecodeError,
        "malformed NewSessionTicket structure",
    )
}

impl<'a> Tls13Ticket<'a> {
    pub(crate) fn parse_legacy_payload(payload: &'a [u8]) -> Result<Self> {
        if payload.len() > 4 && payload[0] == 4 {
            Self::parse_message(payload)
        } else {
            Self::parse_body(payload)
        }
    }

    pub(crate) fn parse_message(mut message: &'a [u8]) -> Result<Self> {
        let kind = message.try_get_u8().map_err(|_| decode_error())?;
        let length = message.try_get_uint(3).map_err(|_| decode_error())?;
        if kind != 4 || length != message.remaining() as u64 {
            return Err(decode_error());
        }
        Self::parse_body(message)
    }

    pub(crate) fn parse_body(mut body: &'a [u8]) -> Result<Self> {
        let lifetime = body.try_get_u32().map_err(|_| decode_error())?;
        let age_add = body.try_get_u32().map_err(|_| decode_error())?;
        let nonce_len = body.try_get_u8().map_err(|_| decode_error())? as usize;
        let (nonce, rest) = body.split_at_checked(nonce_len).ok_or_else(decode_error)?;
        body = rest;
        let ticket_len = body.try_get_u16().map_err(|_| decode_error())? as usize;
        if ticket_len == 0 {
            return Err(decode_error());
        }
        let (ticket, rest) = body.split_at_checked(ticket_len).ok_or_else(decode_error)?;
        body = rest;
        let extensions_len = body.try_get_u16().map_err(|_| decode_error())? as usize;
        if extensions_len != body.remaining() {
            return Err(decode_error());
        }
        let mut early_data = None;
        // Scan the whole block before interpreting a value, preserving duplicate
        // and framing error precedence independently of extension value order.
        while body.has_remaining() {
            let kind = body.try_get_u16().map_err(|_| decode_error())?;
            let length = body.try_get_u16().map_err(|_| decode_error())? as usize;
            let (payload, rest) = body.split_at_checked(length).ok_or_else(decode_error)?;
            body = rest;
            if kind == 42 {
                if early_data.is_some() {
                    return Err(TlsError::local_alert(
                        AlertDescription::IllegalParameter,
                        "duplicate NewSessionTicket early_data extension",
                    ));
                }
                early_data = Some(payload);
            }
        }
        let early_data = early_data
            .map(|value| {
                value
                    .try_into()
                    .map(u32::from_be_bytes)
                    .map_err(|_| decode_error())
            })
            .transpose()?;
        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            early_data,
        })
    }

    pub(crate) fn into_session(
        self,
        resumption_master_secret: &[u8],
        hkdf_algorithm: HkdfAlgorithm,
        aead_algorithm: AeadAlgorithm,
        cipher_suite: u16,
        alpn: Option<String>,
    ) -> Result<SessionTicketData> {
        let resumption_psk = hkdf_expand_label(
            hkdf_algorithm,
            resumption_master_secret,
            "resumption",
            self.nonce,
            hkdf_algorithm.hash_len(),
        )?;
        Ok(SessionTicketData {
            ticket: self.ticket.to_vec(),
            resumption_psk,
            tls_version: TicketTlsVersion::Tls13,
            used_extended_master_secret: None,
            cipher_suite,
            lifetime_secs: self.lifetime,
            age_add: self.age_add,
            received_at: std::time::Instant::now(),
            alpn,
            alps: AlpsSessionState::Unknown,
            hkdf_algorithm,
            aead_algorithm,
            master_secret: Vec::new(),
            max_early_data_size: self.early_data.unwrap_or(0),
            peer_transport_parameters: None,
        })
    }
}
