//! Immutable finalized ClientHello bytes and bounds-checked offer metadata.

use super::client_hello_wire::ClientHelloWire;
use crate::error::Result;
use crate::profile::types::ext_type;
use crate::wire::Reader;
use std::ops::{Deref, Range};
use std::sync::Arc;

struct FinalizedOffer {
    wire: ClientHelloWire,
    extension_types: Vec<u16>,
    alpn: Vec<Range<usize>>,
    groups: Option<Range<usize>>,
    signature_schemes: Option<Range<usize>>,
    certificate_compression: Option<Range<usize>>,
}

fn codepoint_range(wire: &ClientHelloWire, code: u16) -> Option<Range<usize>> {
    let extension = wire
        .extensions
        .iter()
        .find(|extension| extension.extension_type == code)?;
    let mut reader = Reader::new(&wire.handshake[extension.payload.clone()]);
    let values = match code {
        ext_type::COMPRESS_CERTIFICATE => reader.vector8(),
        ext_type::SUPPORTED_GROUPS | ext_type::SIGNATURE_ALGORITHMS => reader.vector16(),
        _ => return None,
    }
    .ok()?;
    reader.finish().ok()?;
    if values.is_empty() || !values.len().is_multiple_of(2) {
        return None;
    }
    Some(extension.payload.end - values.len()..extension.payload.end)
}

#[derive(Clone)]
pub(crate) struct OfferSnapshot(Arc<FinalizedOffer>);

impl OfferSnapshot {
    /// Called after PSK binders, ECH and all length fields have been finalized.
    pub(crate) fn new(bytes: Vec<u8>, inner: Option<&Self>) -> Result<Self> {
        let wire = ClientHelloWire::from_handshake(bytes)?;
        let mut extension_types: Vec<_> = wire
            .extensions
            .iter()
            .map(|ext| ext.extension_type)
            .collect();
        if let Some(inner) = inner {
            // Before ECH acceptance is known, either offer may authorize a
            // response extension. Payload validation still uses the active one.
            for &code in inner.extension_types() {
                if !extension_types.contains(&code) {
                    extension_types.push(code);
                }
            }
        }
        let alpn = wire
            .extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type::ALPN)
            .and_then(|ext| {
                crate::extensions::alpn::parse_alpn_list_bytes(&wire.handshake[ext.payload.clone()])
            })
            .unwrap_or_default()
            .into_iter()
            .map(|protocol| {
                let start = protocol.as_ptr() as usize - wire.handshake.as_ptr() as usize;
                start..start + protocol.len()
            })
            .collect();
        let groups = codepoint_range(&wire, ext_type::SUPPORTED_GROUPS);
        let signature_schemes = codepoint_range(&wire, ext_type::SIGNATURE_ALGORITHMS);
        let certificate_compression = codepoint_range(&wire, ext_type::COMPRESS_CERTIFICATE);
        Ok(Self(Arc::new(FinalizedOffer {
            wire,
            extension_types,
            alpn,
            groups,
            signature_schemes,
            certificate_compression,
        })))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0.wire.handshake
    }

    pub(crate) fn payload(&self, code: u16) -> Option<&[u8]> {
        self.0
            .wire
            .extensions
            .iter()
            .find(|ext| ext.extension_type == code)
            .map(|ext| &self.bytes()[ext.payload.clone()])
    }

    pub(crate) fn offers_version(&self, version: u16) -> bool {
        match self.payload(ext_type::SUPPORTED_VERSIONS) {
            Some(payload) => crate::extensions::supported_versions::parse_client_versions(payload)
                .is_some_and(|versions| versions.contains(&version)),
            None => version <= self.0.wire.protocol_version,
        }
    }

    pub(crate) fn offers_alpn(&self, protocol: &[u8]) -> bool {
        self.0
            .alpn
            .iter()
            .any(|range| &self.bytes()[range.clone()] == protocol)
    }

    pub(crate) fn offers_group(&self, group: u16) -> bool {
        self.contains_codepoint(&self.0.groups, group)
    }

    pub(crate) fn offers_signature_scheme(&self, scheme: u16) -> bool {
        self.contains_codepoint(&self.0.signature_schemes, scheme)
    }

    pub(crate) fn offers_certificate_compression(&self, algorithm: u16) -> bool {
        self.contains_codepoint(&self.0.certificate_compression, algorithm)
    }

    fn contains_codepoint(&self, range: &Option<Range<usize>>, code: u16) -> bool {
        range.as_ref().is_some_and(|range| {
            self.bytes()[range.clone()]
                .as_chunks::<2>()
                .0
                .iter()
                .any(|value| *value == code.to_be_bytes())
        })
    }

    pub(crate) fn extension_types(&self) -> &[u16] {
        &self.0.extension_types
    }
}

impl Deref for OfferSnapshot {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::client_hello::ClientHelloBuilder;
    use crate::profile::types::{ExtensionSource, TlsProfile};

    fn set_raw_extension(profile: &mut TlsProfile, code: u16, payload: &[u8]) {
        profile
            .extensions
            .iter_mut()
            .find(|extension| extension.extension_type == code)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: crate::crypto::to_hex(payload),
        };
    }

    fn build_offer(profile: &TlsProfile, inner: Option<&OfferSnapshot>) -> OfferSnapshot {
        let bytes = ClientHelloBuilder::new(profile, "example.com")
            .build()
            .unwrap()
            .message;
        OfferSnapshot::new(bytes, inner).unwrap()
    }

    #[test]
    fn raw_codepoint_offers_override_profile_fields() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.supported_groups = vec![0x001d];
        profile.signature_algorithms = vec![0x0804];
        profile.compress_cert_algorithms = Some(vec![2]);
        set_raw_extension(
            &mut profile,
            ext_type::SUPPORTED_GROUPS,
            &[0, 4, 0, 0x17, 0xfe, 0xfe],
        );
        set_raw_extension(
            &mut profile,
            ext_type::SIGNATURE_ALGORITHMS,
            &[0, 4, 4, 3, 0xfe, 0xfe],
        );
        set_raw_extension(
            &mut profile,
            ext_type::COMPRESS_CERTIFICATE,
            &[4, 0, 1, 0xfe, 0xfe],
        );
        let offer = build_offer(&profile, None);
        assert!(offer.offers_group(0x0017));
        assert!(!offer.offers_group(0x001d));
        assert!(offer.offers_signature_scheme(0x0403));
        assert!(!offer.offers_signature_scheme(0x0804));
        assert!(offer.offers_certificate_compression(1));
        assert!(!offer.offers_certificate_compression(2));
        assert!(offer.offers_group(0xfefe));
        assert!(offer.offers_signature_scheme(0xfefe));
        assert!(offer.offers_certificate_compression(0xfefe));
    }

    #[test]
    fn malformed_and_missing_codepoint_offers_authorize_nothing() {
        type Membership = fn(&OfferSnapshot, u16) -> bool;
        let extensions: [(u16, Membership, usize); 3] = [
            (ext_type::SUPPORTED_GROUPS, OfferSnapshot::offers_group, 2),
            (
                ext_type::SIGNATURE_ALGORITHMS,
                OfferSnapshot::offers_signature_scheme,
                2,
            ),
            (
                ext_type::COMPRESS_CERTIFICATE,
                OfferSnapshot::offers_certificate_compression,
                1,
            ),
        ];
        for (code, contains, prefix_length) in extensions {
            let mut profile = crate::profile::presets::chrome_155();
            let payloads: &[&[u8]] = if prefix_length == 2 {
                &[
                    &[],
                    &[0],
                    &[0, 0],
                    &[0, 2, 0],
                    &[0, 3, 0, 1, 0],
                    &[0, 4, 0, 1],
                    &[0, 2, 0, 1, 0, 2],
                ]
            } else {
                &[
                    &[],
                    &[0],
                    &[2, 0],
                    &[3, 0, 1, 0],
                    &[4, 0, 1],
                    &[2, 0, 1, 0, 2],
                ]
            };
            for payload in payloads {
                set_raw_extension(&mut profile, code, payload);
                let offer = build_offer(&profile, None);
                for value in [0, 1, 2, 0x001d, 0x0403] {
                    assert!(
                        !contains(&offer, value),
                        "extension {code:#06x}, payload {payload:?}, value {value:#06x}"
                    );
                }
            }
            profile
                .extensions
                .retain(|extension| extension.extension_type != code);
            let offer = build_offer(&profile, None);
            assert!(!contains(&offer, 0x001d));
            assert!(!contains(&offer, 0x0403));
            assert!(!contains(&offer, 2));
        }
    }

    #[test]
    fn codepoint_metadata_uses_first_occurrence_and_active_offer() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.randomization = None;
        set_raw_extension(&mut profile, ext_type::SUPPORTED_GROUPS, &[0, 2, 0, 0x17]);
        let inner = build_offer(&profile, None);
        assert!(inner.offers_group(0x0017));

        let valid_extension = profile
            .extensions
            .iter()
            .find(|extension| extension.extension_type == ext_type::SUPPORTED_GROUPS)
            .unwrap()
            .clone();
        set_raw_extension(&mut profile, ext_type::SUPPORTED_GROUPS, &[0, 0]);
        profile.extensions.push(valid_extension);
        let outer = build_offer(&profile, Some(&inner));
        assert!(outer
            .extension_types()
            .contains(&ext_type::SUPPORTED_GROUPS));
        assert!(!outer.offers_group(0x0017));
    }

    #[test]
    fn finalized_offer_preserves_storage_and_raw_protocol_identity() {
        use crate::handshake::client_hello::ClientHelloBuilder;
        use crate::profile::types::ExtensionSource;
        let mut profile = crate::profile::presets::chrome_155();
        profile
            .extensions
            .iter_mut()
            .find(|ext| ext.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "00020180".into(),
        };
        let bytes = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .unwrap()
            .message;
        let original = bytes.as_ptr();
        let offer = OfferSnapshot::new(bytes, None).unwrap();
        let clone = offer.clone();
        assert_eq!(offer.bytes().as_ptr(), original);
        assert_eq!(clone.bytes().as_ptr(), original);
        assert!(offer.offers_alpn(&[0x80]));
        assert!(!offer.offers_alpn(b"h2"));
        assert!(offer.offers_version(0x0304));
        assert!(!offer.offers_version(0x0302));
        assert_eq!(offer.payload(ext_type::ALPN), Some(&[0, 2, 1, 0x80][..]));
    }

    #[test]
    fn finalized_offer_rejects_incomplete_and_trailing_messages() {
        use crate::handshake::client_hello::ClientHelloBuilder;
        let profile = crate::profile::presets::chrome_155();
        let bytes = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .unwrap()
            .message;
        assert!(OfferSnapshot::new(bytes[..bytes.len() - 1].to_vec(), None).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(OfferSnapshot::new(trailing, None).is_err());
    }
}
