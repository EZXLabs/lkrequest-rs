//! Client state before a protocol version has been selected.

use std::sync::Arc;

use aws_lc_rs::digest;

use super::client_hello::{
    profile_offers_alps_protocol, ClientHelloBuilder, EchRetryState, ExtensionOrder,
};
use super::offer::OfferSnapshot;
use crate::config::{CompiledClientConfig, ConnectionOverlay};
use crate::crypto::hkdf::{HkdfAlgorithm, HkdfPrk};
use crate::crypto::kx::EphemeralKeyPair;
use crate::error::{Result, TlsError};
use crate::extensions::grease::GreaseValues;
use crate::extensions::pre_shared_key::{self, PskIdentity};
use crate::profile::types::TlsProfile;
use crate::session_store::{AlpsSessionState, SessionTicketData};

pub(super) struct HelloInputs<'a> {
    pub profile: &'a TlsProfile,
    pub hello_profile: &'a TlsProfile,
    pub compiled: Option<&'a CompiledClientConfig>,
    pub overlay: Option<&'a ConnectionOverlay>,
    pub hostname: &'a str,
    pub alps_payload: Option<&'a [u8]>,
    pub ech_config: Option<&'a [u8]>,
    pub tls12_ticket: Option<Vec<u8>>,
    pub tls12_session_id: Option<Vec<u8>>,
    pub quic_parameters: Option<&'a [u8]>,
    pub quic: bool,
}

/// All mandatory initial-flight values exist before the version-specific state.
pub(super) struct PreparedHello {
    pub offer: OfferSnapshot,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub key_pairs: Vec<EphemeralKeyPair>,
    pub grease: GreaseValues,
    pub order: ExtensionOrder,
    pub ech_grease: Option<Vec<u8>>,
    pub ech_offered: bool,
    pub inner: Option<OfferSnapshot>,
    pub ech_retry: Option<EchRetryState>,
    pub psk_ticket: Option<SessionTicketData>,
    pub tls12_ticket: Option<Vec<u8>>,
    pub early_secret: Option<HkdfPrk>,
}

pub(super) struct ClientStart {
    pub compiled: Arc<CompiledClientConfig>,
    pub overlay: Option<Arc<ConnectionOverlay>>,
    pub hello: PreparedHello,
}

impl PreparedHello {
    pub(super) fn build(
        input: HelloInputs<'_>,
        psk_ticket: Option<SessionTicketData>,
    ) -> Result<Self> {
        let alps_compatible = psk_ticket.as_ref().is_none_or(|ticket| {
            alps_allows_early_data(
                input.profile,
                input.compiled,
                input.overlay,
                input.alps_payload,
                ticket,
            )
        });
        let mut builder = ClientHelloBuilder::new(input.hello_profile, input.hostname)
            .with_compiled(input.compiled)
            .with_overlay(input.overlay)
            .with_handshake_extensions(input.alps_payload.is_some(), alps_compatible);
        if let Some(config) = input.ech_config {
            builder = builder.with_ech_config(config.to_vec());
        }
        if let Some(ticket) = &input.tls12_ticket {
            builder = builder.with_session_ticket_data(ticket.clone());
        }
        if let Some(session_id) = input.tls12_session_id {
            builder = builder.with_session_id(session_id);
        }
        if let Some(parameters) = input.quic_parameters {
            builder = builder.with_quic_transport_parameters(parameters.to_vec());
        }
        if alps_compatible
            && psk_ticket
                .as_ref()
                .is_some_and(|ticket| ticket.max_early_data_size > 0)
        {
            builder = builder.with_early_data();
        }
        if input.ech_config.is_some() {
            if let Some(ticket) = &psk_ticket {
                builder = builder.with_psk_offer(
                    ticket.ticket.clone(),
                    ticket.obfuscated_ticket_age(),
                    ticket.resumption_psk.clone(),
                    ticket.hkdf_algorithm,
                    Vec::new(),
                );
            }
        }
        let psk_length = psk_ticket.as_ref().map_or(0, |ticket| {
            pre_shared_key::psk_extension_length(
                ticket.ticket.len(),
                ticket.hkdf_algorithm.hash_len(),
            )
        });
        let output = builder.build_with_psk_hint(psk_length)?;
        let random = output.message[6..38].try_into().unwrap();
        let sid_length = usize::from(output.message[38]);
        let session_id = output.message[39..39 + sid_length].to_vec();
        if input.quic && !session_id.is_empty() {
            return Err(TlsError::HandshakeFailure(
                "QUIC ClientHello must use an empty legacy_session_id".into(),
            ));
        }
        let inner = output
            .inner_hello
            .map(|bytes| OfferSnapshot::new(bytes, None))
            .transpose()?;
        let (bytes, early_secret) = match &psk_ticket {
            Some(ticket) if !output.ech_offered => {
                let (bytes, secret) = append_psk_extension(output.message, ticket, None)?;
                (bytes, Some(secret))
            }
            Some(ticket) => (
                output.message,
                Some(pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?),
            ),
            None => (output.message, None),
        };
        let offer = OfferSnapshot::new(bytes, inner.as_ref())?;
        Ok(Self {
            offer,
            random,
            session_id,
            key_pairs: output.key_shares,
            grease: output.grease_values,
            order: output.shuffled_extensions,
            ech_grease: output.ech_grease_extension,
            ech_offered: output.ech_offered,
            inner,
            ech_retry: output.ech_retry_state,
            psk_ticket,
            tls12_ticket: input.tls12_ticket,
            early_secret,
        })
    }

    pub(super) fn ech_public_name(&self) -> Option<String> {
        if !self.ech_offered {
            return None;
        }
        let name = &self.ech_retry.as_ref()?.config.public_name;
        (!name.is_empty()).then(|| name.clone())
    }
}

pub(super) fn alps_allows_early_data(
    profile: &TlsProfile,
    compiled: Option<&CompiledClientConfig>,
    overlay: Option<&ConnectionOverlay>,
    payload: Option<&[u8]>,
    ticket: &SessionTicketData,
) -> bool {
    match &ticket.alps {
        AlpsSessionState::Unknown | AlpsSessionState::NotNegotiated => true,
        AlpsSessionState::Negotiated {
            client_settings, ..
        } => {
            payload == Some(client_settings.as_slice())
                && ticket.alpn.as_deref().is_some_and(|protocol| {
                    if let Some(overlay) = overlay {
                        return overlay.offers_alps(protocol.as_bytes());
                    }
                    profile_offers_alps_protocol(profile, protocol.as_bytes(), compiled)
                })
        }
    }
}

pub(super) fn append_psk_extension(
    mut message: Vec<u8>,
    ticket: &SessionTicketData,
    prefix: Option<&digest::Context>,
) -> Result<(Vec<u8>, HkdfPrk)> {
    let binder_length = ticket.hkdf_algorithm.hash_len();
    let identities = [PskIdentity {
        identity: ticket.ticket.clone(),
        obfuscated_ticket_age: ticket.obfuscated_ticket_age(),
    }];
    let (extension, binder_offset) =
        pre_shared_key::encode_psk_extension(&identities, binder_length);
    let old_length = message.len();
    let sid_length = usize::from(message[38]);
    let suites_start = 39 + sid_length;
    let suites_length = usize::from(u16::from_be_bytes([
        message[suites_start],
        message[suites_start + 1],
    ]));
    let compression_start = suites_start + 2 + suites_length;
    let extensions_start = compression_start + 1 + usize::from(message[compression_start]);
    let extensions_length = usize::from(u16::from_be_bytes([
        message[extensions_start],
        message[extensions_start + 1],
    ]));
    let new_extensions_length =
        u16::try_from(extensions_length + extension.len()).map_err(|_| {
            TlsError::InvalidProfile("PSK extension exceeds ClientHello extension budget".into())
        })?;
    message.extend_from_slice(&extension);
    let body_length = (message.len() - 4) as u32;
    message[1..4].copy_from_slice(&body_length.to_be_bytes()[1..]);
    message[extensions_start..extensions_start + 2]
        .copy_from_slice(&new_extensions_length.to_be_bytes());
    let truncated = &message[..message.len() - pre_shared_key::binders_size(1, binder_length)];
    let mut transcript = prefix.cloned().unwrap_or_else(|| {
        digest::Context::new(match ticket.hkdf_algorithm {
            HkdfAlgorithm::Sha256 => &digest::SHA256,
            HkdfAlgorithm::Sha384 => &digest::SHA384,
        })
    });
    transcript.update(truncated);
    let binder = pre_shared_key::compute_psk_binder(
        ticket.hkdf_algorithm,
        &ticket.resumption_psk,
        transcript.finish().as_ref(),
    )?;
    let offset = old_length + binder_offset;
    message[offset..offset + binder_length].copy_from_slice(&binder);
    let secret =
        pre_shared_key::compute_early_secret(ticket.hkdf_algorithm, &ticket.resumption_psk)?;
    Ok((message, secret))
}
