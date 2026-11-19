//! Static offer facts retained independently of per-connection encoders.

use std::{collections::BTreeMap, sync::Arc};

use crate::profile::types::{ext_type, ExtensionSource, TlsProfile};

pub(super) type Cached<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProtocolSource {
    Generated,
    Raw,
    Unsupported,
}

#[derive(Debug)]
pub(super) struct ProtocolEntry {
    pub index: usize,
    pub source: ProtocolSource,
    pub bytes: Cached<Arc<[Vec<u8>]>>,
}

#[derive(Debug)]
pub(super) struct ExtensionMetadata {
    protocols: [Box<[ProtocolEntry]>; 3],
    pub alpn: Cached<Arc<[Vec<u8>]>>,
    pub alpn_offer: Cached<Arc<[Vec<u8>]>>,
    pub alps: Cached<Arc<[Vec<u8>]>>,
    pub trust_anchors: Box<[usize]>,
    pub generated_tai_recovery: bool,
    alps_offers: Box<[Arc<[u8]>]>,
}

impl ExtensionMetadata {
    pub fn compile(profile: &TlsProfile, decoded: &BTreeMap<String, Arc<[u8]>>) -> Self {
        let mut protocols: [Vec<ProtocolEntry>; 3] = Default::default();
        for (index, spec) in profile.extensions.iter().enumerate() {
            let slot = match spec.extension_type {
                ext_type::ALPN => 0,
                ext_type::APPLICATION_SETTINGS => 1,
                ext_type::APPLICATION_SETTINGS_NEW => 2,
                _ => continue,
            };
            let (source, bytes) = match &spec.source {
                ExtensionSource::Auto => {
                    let names = if slot == 0 {
                        &profile.alpn_protocols[..]
                    } else {
                        profile.alps_protocols.as_deref().unwrap_or_default()
                    };
                    (
                        ProtocolSource::Generated,
                        Ok(names.iter().map(|name| name.as_bytes().to_vec()).collect()),
                    )
                }
                ExtensionSource::RawBytes { data } => {
                    let bytes: Cached<Arc<[Vec<u8>]>> =
                        crate::extensions::alpn::parse_alpn_list_bytes(&decoded[data])
                            .map(|names| names.into_iter().map(ToOwned::to_owned).collect())
                            .ok_or("invalid raw protocol list in overlay");
                    (ProtocolSource::Raw, bytes)
                }
                _ => (
                    ProtocolSource::Unsupported,
                    Err("protocol overlay requires generated or raw protocol sources"),
                ),
            };
            protocols[slot].push(ProtocolEntry {
                index,
                source,
                bytes,
            });
        }
        let protocols = protocols.map(Vec::into_boxed_slice);
        let alpn_offer = protocols[0]
            .first()
            .map_or_else(|| Ok(Arc::from([])), |entry| entry.bytes.clone());
        let first = |entries: &[ProtocolEntry]| {
            entries
                .first()
                .map_or_else(|| Ok(Arc::from([])), |entry| entry.bytes.clone())
                .and_then(|names| {
                    super::overlay::validate_protocol_names(&names)?;
                    Ok(names)
                })
        };
        let alpn = first(&protocols[0]);
        let alps = first(&protocols[1]).and_then(|old| {
            let new = first(&protocols[2])?;
            if old.is_empty() {
                return Ok(new);
            }
            if new.iter().all(|name| old.contains(name)) {
                return Ok(old);
            }
            let mut merged = old.to_vec();
            for name in new.iter() {
                if !merged.contains(name) {
                    merged.push(name.clone());
                }
            }
            super::overlay::validate_protocol_names(&merged)?;
            Ok(merged.into())
        });
        let trust_anchors: Box<[usize]> = profile
            .extensions
            .iter()
            .enumerate()
            .filter_map(|(index, spec)| {
                (spec.extension_type == ext_type::TRUST_ANCHOR_IDS).then_some(index)
            })
            .collect();
        let generated_tai_recovery = trust_anchors.len() == 1
            && matches!(
                profile.extensions[trust_anchors[0]].source,
                ExtensionSource::Auto | ExtensionSource::TrustAnchorIds { .. }
            );
        let mut alps_offers = Vec::new();
        for entry in protocols[1..].iter().flatten() {
            if let Ok(names) = &entry.bytes {
                alps_offers.extend(names.iter().map(|name| Arc::from(name.as_slice())));
            } else if let ExtensionSource::TrustAnchorIds { ids, .. } =
                &profile.extensions[entry.index].source
            {
                alps_offers.extend(ids.iter().map(|id| decoded[id].clone()));
            }
        }
        Self {
            protocols,
            alpn,
            alpn_offer,
            alps,
            trust_anchors,
            generated_tai_recovery,
            alps_offers: alps_offers.into(),
        }
    }

    pub fn protocols(&self, code: u16) -> &[ProtocolEntry] {
        &self.protocols[match code {
            ext_type::ALPN => 0,
            ext_type::APPLICATION_SETTINGS => 1,
            ext_type::APPLICATION_SETTINGS_NEW => 2,
            _ => unreachable!("not a protocol-list extension"),
        }]
    }

    pub fn offers_alps(&self, protocol: &[u8]) -> bool {
        self.alps_offers
            .iter()
            .any(|name| name.as_ref() == protocol)
    }
}
