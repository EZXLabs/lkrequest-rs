//! Validated per-attempt encoding differences. No tickets or secrets live here.

use std::{collections::BTreeMap, sync::Arc};

use crate::error::{Result, TlsError};
use crate::extensions::{alpn::Alpn, Extension};
use crate::profile::types::{ext_type, ExtensionSource};
use crate::trust_anchor::TrustAnchorId;

use super::{
    metadata::{Cached, ProtocolSource},
    CompiledClientConfig,
};

/// Generated per-connection ClientHello values; raw payloads are never rewritten.
#[derive(Debug, Clone, Default)]
pub struct ClientHelloOverrides {
    pub alpn_protocols: Option<Vec<String>>,
    /// An empty list disables generated ALPS advertisements.
    pub alps_protocols: Option<Vec<String>>,
    pub trust_anchor_ids: Option<Vec<TrustAnchorId>>,
}

#[derive(Debug)]
pub(crate) struct ConnectionOverlay {
    alpn: Cached<Arc<[Vec<u8>]>>,
    alps: Cached<Arc<[Vec<u8>]>>,
    encoded: BTreeMap<usize, Vec<u8>>,
}

impl ConnectionOverlay {
    pub(super) fn alpn(&self) -> Result<&[Vec<u8>]> {
        self.alpn.as_deref().map_err(|error| invalid(error))
    }
    pub(crate) fn offers_alpn(&self, protocol: &[u8]) -> bool {
        self.alpn
            .as_ref()
            .is_ok_and(|names| names.iter().any(|name| name == protocol))
    }
    pub(crate) fn offers_alps(&self, protocol: &[u8]) -> bool {
        self.alps
            .as_ref()
            .is_ok_and(|names| names.iter().any(|name| name == protocol))
    }
    pub(crate) fn encode(&self, index: usize, output: &mut Vec<u8>) -> bool {
        let Some(bytes) = self.encoded.get(&index) else {
            return false;
        };
        output.extend_from_slice(bytes);
        true
    }
}

impl CompiledClientConfig {
    pub(crate) fn connection_overlay(
        &self,
        inputs: impl std::borrow::Borrow<ClientHelloOverrides>,
    ) -> Result<Arc<ConnectionOverlay>> {
        let inputs = inputs.borrow();
        let profile = &self.hello_profile;
        let resolve = |names: Option<&[String]>,
                       base: &Cached<Arc<[Vec<u8>]>>|
         -> Result<Cached<Arc<[Vec<u8>]>>> {
            match names {
                Some(names) => {
                    validate_protocol_names(names).map_err(invalid)?;
                    Ok(Ok(names
                        .iter()
                        .map(|name| name.as_bytes().to_vec())
                        .collect()))
                }
                None => Ok(base.clone()),
            }
        };
        let alpn = resolve(inputs.alpn_protocols.as_deref(), &self.metadata.alpn)?;
        let alps = resolve(inputs.alps_protocols.as_deref(), &self.metadata.alps)?;
        if inputs.alpn_protocols.is_some() || inputs.alps_protocols.is_some() {
            let alps = alps.as_ref().map_err(|error| invalid(error))?;
            if !alps.is_empty() {
                let alpn = alpn.as_ref().map_err(|error| invalid(error))?;
                if alps.iter().any(|name| !alpn.contains(name)) {
                    return Err(invalid("ALPS overlay names a protocol absent from ALPN"));
                }
            }
        }
        let mut encoded = BTreeMap::new();
        for (code, protocols) in [
            (ext_type::ALPN, inputs.alpn_protocols.as_deref()),
            (
                ext_type::APPLICATION_SETTINGS,
                inputs.alps_protocols.as_deref(),
            ),
            (
                ext_type::APPLICATION_SETTINGS_NEW,
                inputs.alps_protocols.as_deref(),
            ),
        ] {
            let Some(protocols) = protocols else { continue };
            let entries = self.metadata.protocols(code);
            let entry = entries.first();
            if entries.len() > 1 {
                return Err(invalid(
                    "connection overlay cannot replace duplicate extension sources",
                ));
            }
            if code == ext_type::ALPN && !protocols.is_empty() && entry.is_none() {
                return Err(invalid("ALPN overlay requires an existing extension"));
            }
            let Some(entry) = entry else { continue };
            if entry.source == ProtocolSource::Raw {
                let actual = entry.bytes.as_ref().map_err(|error| invalid(error))?;
                if !actual
                    .iter()
                    .map(Vec::as_slice)
                    .eq(protocols.iter().map(|p| p.as_bytes()))
                {
                    return Err(invalid(
                        "raw protocol list conflicts with connection overlay",
                    ));
                }
            } else {
                if entry.source != ProtocolSource::Generated {
                    return Err(invalid("connection overlay requires a generated extension"));
                }
                let mut bytes = Vec::new();
                if !protocols.is_empty() {
                    Alpn {
                        protocols: protocols.to_vec(),
                    }
                    .encode(&mut bytes);
                    bytes[..2].copy_from_slice(&code.to_be_bytes());
                }
                encoded.insert(entry.index, bytes);
            }
        }
        if inputs
            .alps_protocols
            .as_ref()
            .is_some_and(|v| !v.is_empty())
            && self
                .metadata
                .protocols(ext_type::APPLICATION_SETTINGS)
                .is_empty()
            && self
                .metadata
                .protocols(ext_type::APPLICATION_SETTINGS_NEW)
                .is_empty()
        {
            return Err(invalid("ALPS overlay requires an existing extension"));
        }
        if let Some(ids) = inputs.trust_anchor_ids.as_ref() {
            if self.metadata.trust_anchors.len() > 1 {
                return Err(invalid(
                    "connection overlay cannot replace duplicate extension sources",
                ));
            }
            let bytes = crate::trust_anchor::encode_list(ids)?;
            let spec = self
                .metadata
                .trust_anchors
                .first()
                .map(|&index| &profile.extensions[index])
                .ok_or_else(|| invalid("trust anchor overlay requires an existing extension"))?;
            if let ExtensionSource::RawBytes { data } = &spec.source {
                if self.decoded[data].as_ref() != bytes {
                    return Err(invalid(
                        "raw trust anchor list conflicts with connection overlay",
                    ));
                }
            } else if matches!(
                spec.source,
                ExtensionSource::Auto | ExtensionSource::TrustAnchorIds { .. }
            ) {
                let mut wire = Vec::new();
                crate::extensions::generic::GenericExtension::new(
                    ext_type::TRUST_ANCHOR_IDS,
                    bytes,
                )
                .encode(&mut wire);
                encoded.insert(self.metadata.trust_anchors[0], wire);
            } else {
                return Err(invalid(
                    "trust anchor overlay requires a generated extension",
                ));
            }
        }
        Ok(Arc::new(ConnectionOverlay {
            alpn,
            alps,
            encoded,
        }))
    }
}

fn invalid(message: &str) -> TlsError {
    TlsError::InvalidProfile(message.into())
}

pub(super) fn validate_protocol_names<T: AsRef<[u8]>>(
    protocols: &[T],
) -> std::result::Result<(), &'static str> {
    let mut length = 0usize;
    for protocol in protocols {
        let protocol = protocol.as_ref();
        if protocol.is_empty() || protocol.len() > 255 {
            return Err("protocol name must contain 1..255 bytes");
        }
        length += 1 + protocol.len();
    }
    if length > u16::MAX as usize - 2 {
        return Err("protocol extension exceeds 65535 bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompileOptions, Transport};
    use crate::handshake::{client_hello::ClientHelloBuilder, client_hello_wire::ClientHelloWire};

    #[test]
    fn unrelated_tai_overlay_preserves_opaque_raw_protocols() {
        let mut profile = crate::profile::presets::chrome_155();
        profile
            .extensions
            .iter_mut()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "000201ff".into(),
        };
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        let overlay = base
            .connection_overlay(ClientHelloOverrides {
                trust_anchor_ids: Some(vec![TrustAnchorId::new(vec![1]).unwrap()]),
                ..Default::default()
            })
            .expect("TAI does not require text ALPN");
        let wire = ClientHelloWire::parse(
            &ClientHelloBuilder::new(&base.hello_profile, "localhost")
                .with_compiled(Some(&base))
                .with_overlay(Some(&overlay))
                .build()
                .unwrap()
                .message,
        )
        .unwrap();
        let alpn = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap();
        assert_eq!(&wire.handshake[alpn.payload.clone()], &[0, 2, 1, 0xff]);
        let tai = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .unwrap();
        assert_eq!(&wire.handshake[tai.payload.clone()], &[0, 2, 1, 1]);
        assert!(base.offers_alpn(&[0xff], Some(&overlay)));
        let disabled_alps = base
            .connection_overlay(ClientHelloOverrides {
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            })
            .unwrap();
        assert!(base.offers_alpn(&[0xff], Some(&disabled_alps)));
        assert!(!disabled_alps.offers_alps(b"h2"));
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["h2".into()]),
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn tai_only_overlays_share_static_protocol_metadata() {
        let base = CompiledClientConfig::compile(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        for value in [1, 2] {
            let overlay = base
                .connection_overlay(ClientHelloOverrides {
                    trust_anchor_ids: Some(vec![TrustAnchorId::new(vec![value]).unwrap()]),
                    ..Default::default()
                })
                .unwrap();
            assert!(Arc::ptr_eq(
                overlay.alpn.as_ref().unwrap(),
                base.metadata.alpn.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                overlay.alps.as_ref().unwrap(),
                base.metadata.alps.as_ref().unwrap()
            ));
        }
    }

    #[test]
    fn ticket_protocol_membership_uses_first_raw_or_generated_offer_and_overlay() {
        for payload in ["0003026832", "000201ff"] {
            let mut profile = crate::profile::presets::chrome_155();
            profile.alpn_protocols = vec!["http/1.1".into()];
            profile
                .extensions
                .iter_mut()
                .find(|e| e.extension_type == ext_type::ALPN)
                .unwrap()
                .source = ExtensionSource::RawBytes {
                data: payload.into(),
            };
            profile
                .extensions
                .push(crate::profile::types::ExtensionSpec {
                    extension_type: ext_type::ALPN,
                    source: ExtensionSource::RawBytes {
                        data: "0003026833".into(),
                    },
                });
            let base = CompiledClientConfig::compile(
                profile,
                Transport::Tcp,
                CompileOptions::compatibility(),
            )
            .unwrap();
            assert!(base.offers_alpn(
                if payload == "0003026832" {
                    b"h2"
                } else {
                    &[0xff]
                },
                None
            ));
            assert!(!base.offers_alpn(b"http/1.1", None));
            assert!(!base.offers_alpn(b"h3", None));
        }
        let base = CompiledClientConfig::compile(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let overlay = base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["http/1.1".into()]),
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            })
            .unwrap();
        assert!(base.offers_alpn(b"h2", None));
        assert!(!base.offers_alpn(b"h2", Some(&overlay)));
        assert!(base.offers_alpn(b"http/1.1", Some(&overlay)));
    }

    #[test]
    fn opaque_raw_protocol_metadata_preserves_bytes_during_shared_recovery() {
        let mut profile = crate::profile::presets::chrome_155();
        profile
            .extensions
            .iter_mut()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "000201ff".into(),
        };
        profile
            .extensions
            .iter_mut()
            .find(|e| {
                matches!(
                    e.extension_type,
                    ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW
                )
            })
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "000201ff".into(),
        };
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        assert_eq!(
            base.metadata.protocols(ext_type::ALPN)[0]
                .bytes
                .as_ref()
                .unwrap()
                .as_ref(),
            &[vec![0xff]]
        );
        assert!(base
            .validate_connection(&crate::config::ConnectionInputs::new("localhost", 443))
            .is_ok());
        let template = crate::config::ClientConfigTemplate::from_compiled(base.clone());
        let (retry, overrides) = template
            .trust_anchor_recovery(
                vec![TrustAnchorId::new(vec![1]).unwrap()],
                &ClientHelloOverrides::default(),
            )
            .unwrap();
        assert_eq!(
            overrides.trust_anchor_ids,
            Some(vec![TrustAnchorId::new(vec![1]).unwrap()])
        );
        let retry = retry.compile().unwrap();
        assert!(Arc::ptr_eq(&base, &retry));
        let overlay = retry.connection_overlay(overrides).unwrap();
        let wire = ClientHelloWire::parse(
            &ClientHelloBuilder::new(&retry.hello_profile, "localhost")
                .with_compiled(Some(&retry))
                .with_overlay(Some(&overlay))
                .build()
                .unwrap()
                .message,
        )
        .unwrap();
        let ext = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap();
        assert_eq!(&wire.handshake[ext.payload.clone()], &[0, 2, 1, 0xff]);
        let alps = wire
            .extensions
            .iter()
            .find(|e| {
                matches!(
                    e.extension_type,
                    ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW
                )
            })
            .unwrap();
        assert_eq!(&wire.handshake[alps.payload.clone()], &[0, 2, 1, 0xff]);
        assert!(overlay.offers_alps(&[0xff]));
        let tai = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .unwrap();
        assert_eq!(&wire.handshake[tai.payload.clone()], &[0, 2, 1, 1]);
    }

    #[test]
    fn shared_recovery_keeps_overrides_and_is_atomic_on_invalid_ids() {
        let template = crate::config::ClientConfigTemplate::new(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        );
        let compiled = template.compile().unwrap();
        let inputs = ClientHelloOverrides {
            alpn_protocols: Some(vec!["http/1.1".into()]),
            alps_protocols: Some(Vec::new()),
            ..Default::default()
        };
        let id = TrustAnchorId::new(vec![1]).unwrap();
        let (retry, overrides) = template
            .trust_anchor_recovery(vec![id.clone()], &inputs)
            .unwrap();
        assert!(Arc::ptr_eq(&compiled, &retry.compile().unwrap()));
        assert_eq!(overrides.alpn_protocols, inputs.alpn_protocols);
        assert_eq!(overrides.alps_protocols, inputs.alps_protocols);
        assert_eq!(overrides.trust_anchor_ids, Some(vec![id.clone()]));
        assert!(template
            .trust_anchor_recovery(vec![id; 32767], &inputs)
            .is_err());
        assert!(inputs.trust_anchor_ids.is_none());
        assert!(Arc::ptr_eq(&compiled, &template.compile().unwrap()));
    }

    #[test]
    fn duplicate_tai_sources_remain_distinct_and_cannot_be_overlaid() {
        let mut profile = crate::profile::presets::chrome_155();
        let original = profile
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .unwrap()
            .clone();
        profile.extensions.push(original);
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        assert!(ClientHelloBuilder::new(&base.hello_profile, "localhost")
            .with_compiled(Some(&base))
            .build()
            .is_ok());
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                trust_anchor_ids: Some(vec![TrustAnchorId::new(vec![1]).unwrap()]),
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn connection_inputs_resolve_effective_protocol_constraints() {
        let base = CompiledClientConfig::compile(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let mut inputs = crate::config::ConnectionInputs::new("localhost", 443);
        assert!(base.resolve_overlay(&inputs).unwrap().is_none());
        inputs.hello_overrides = ClientHelloOverrides {
            alpn_protocols: Some(vec!["http/1.1".into()]),
            alps_protocols: Some(Vec::new()),
            ..Default::default()
        };
        inputs.required_alpn = Some(vec!["http/1.1".into()]);
        assert!(base.validate_connection(&inputs).is_ok());
        assert_eq!(
            base.resolve_overlay(&inputs)
                .unwrap()
                .unwrap()
                .alpn()
                .unwrap(),
            [b"http/1.1".to_vec()]
        );
        inputs.required_alpn = Some(vec!["h2".into()]);
        assert!(base.validate_connection(&inputs).is_err());
    }

    #[test]
    fn default_inputs_preserve_legacy_raw_values_and_explicit_overlays_read_actual_offer() {
        let mut profile = crate::profile::presets::chrome_155();
        profile.extensions.retain(|e| {
            !matches!(
                e.extension_type,
                ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW
            )
        });
        profile.alps_protocols = None;
        profile
            .extensions
            .iter_mut()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap()
            .source = ExtensionSource::RawBytes {
            data: "000908687474702f312e31".into(),
        };
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        let mut inputs = crate::config::ConnectionInputs::new("localhost", 443);
        assert!(base.validate_connection(&inputs).is_ok());
        assert!(base.resolve_overlay(&inputs).unwrap().is_none());
        inputs.hello_overrides.alps_protocols = Some(Vec::new());
        inputs.required_alpn = Some(vec!["http/1.1".into()]);
        assert!(base.validate_connection(&inputs).is_ok());
        assert_eq!(
            base.resolve_overlay(&inputs)
                .unwrap()
                .unwrap()
                .alpn()
                .unwrap(),
            [b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn generated_overlay_is_atomic_and_keeps_base_immutable() {
        let base = CompiledClientConfig::compile(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let original = base.profile().alpn_protocols.clone();
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["http/1.1".into()]),
                ..Default::default()
            })
            .is_err());
        let overlay = base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["http/1.1".into()]),
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(overlay.alpn().unwrap(), [b"http/1.1".to_vec()]);
        assert!(!overlay.offers_alps(b"h2"));
        let wire = ClientHelloWire::parse(
            &ClientHelloBuilder::new(&base.hello_profile, "localhost")
                .with_compiled(Some(&base))
                .with_overlay(Some(&overlay))
                .build()
                .unwrap()
                .message,
        )
        .unwrap();
        let ext = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap();
        assert_eq!(
            crate::extensions::alpn::parse_alpn_list_bytes(&wire.handshake[ext.payload.clone()])
                .unwrap(),
            [b"http/1.1".as_slice()]
        );
        assert!(!wire.extensions.iter().any(|e| matches!(
            e.extension_type,
            ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW
        )));
        assert_eq!(base.profile().alpn_protocols, original);
    }

    #[test]
    fn raw_sources_and_protocol_limits_cannot_be_bypassed_by_overlays() {
        let mut profile = crate::profile::presets::chrome_155();
        let alpn = profile
            .extensions
            .iter_mut()
            .find(|e| e.extension_type == ext_type::ALPN)
            .unwrap();
        alpn.source = ExtensionSource::RawBytes {
            data: "000c02683208687474702f312e31".into(),
        };
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["http/1.1".into()]),
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            })
            .is_err());
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["".into()]),
                ..Default::default()
            })
            .is_err());
        assert!(base
            .connection_overlay(ClientHelloOverrides {
                alpn_protocols: Some(vec!["x".repeat(256)]),
                ..Default::default()
            })
            .is_err());
        assert!(base
            .connection_overlay(ClientHelloOverrides::default())
            .is_ok());
    }

    #[test]
    fn flight_suppression_wins_over_generated_alps_override() {
        let base = CompiledClientConfig::compile(
            crate::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let overlay = base
            .connection_overlay(ClientHelloOverrides {
                alps_protocols: Some(vec!["h2".into()]),
                ..Default::default()
            })
            .unwrap();
        let wire = ClientHelloWire::parse(
            &ClientHelloBuilder::new(&base.hello_profile, "localhost")
                .with_compiled(Some(&base))
                .with_overlay(Some(&overlay))
                .with_handshake_extensions(false, false)
                .build()
                .unwrap()
                .message,
        )
        .unwrap();
        assert!(!wire.extensions.iter().any(|e| matches!(
            e.extension_type,
            ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW
        )));
    }
}
