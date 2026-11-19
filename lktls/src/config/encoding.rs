//! Immutable extension operations, with per-connection GREASE substitutions.

use std::{collections::BTreeMap, sync::Arc};

use crate::extensions::grease::{GreaseIndex, GreaseValues};
use crate::handshake::client_hello::ClientHelloBuilder;
use crate::profile::types::{ext_type, ExtensionSource, TlsProfile};

use super::CompileError;

#[derive(Debug)]
pub(crate) struct EncodingPlan {
    operations: Box<[Operation]>,
}

#[derive(Debug)]
pub(crate) enum Operation {
    Fixed {
        bytes: Box<[u8]>,
        grease: Option<(usize, GreaseIndex)>,
    },
    Auto,
    Grease,
    TrustAnchors {
        ids: Box<[Arc<[u8]>]>,
        shuffle: bool,
    },
}

impl EncodingPlan {
    pub(super) fn compile(
        profile: &TlsProfile,
        decoded: &BTreeMap<String, Arc<[u8]>>,
    ) -> Result<Self, CompileError> {
        let builder = ClientHelloBuilder::new(profile, "");
        let mut operations = Vec::with_capacity(profile.extensions.len());
        for spec in &profile.extensions {
            let Some(bytes) = builder
                .compile_extension(spec)
                .map_err(|e| CompileError::Invalid(e.to_string()))?
            else {
                operations.push(match &spec.source {
                    ExtensionSource::Auto => Operation::Auto,
                    ExtensionSource::Grease => Operation::Grease,
                    ExtensionSource::TrustAnchorIds { ids, shuffle } => Operation::TrustAnchors {
                        ids: ids.iter().map(|id| decoded[id].clone()).collect(),
                        shuffle: *shuffle,
                    },
                    ExtensionSource::RawBytes { .. } => unreachable!("raw payloads are fixed"),
                });
                continue;
            };
            let grease = if matches!(spec.source, ExtensionSource::Auto) {
                match spec.extension_type {
                    ext_type::SUPPORTED_GROUPS if profile.grease.supported_groups => {
                        Some((6, GreaseIndex::Group))
                    }
                    ext_type::SIGNATURE_ALGORITHMS if profile.grease.signature_algorithms => {
                        Some((6, GreaseIndex::SignatureAlgorithm))
                    }
                    ext_type::SUPPORTED_VERSIONS if profile.grease.supported_versions => {
                        Some((5, GreaseIndex::Version))
                    }
                    _ => None,
                }
            } else {
                None
            };
            operations.push(Operation::Fixed {
                bytes: bytes.into(),
                grease,
            });
        }
        Ok(Self {
            operations: operations.into(),
        })
    }

    pub(crate) fn operation(&self, index: usize) -> &Operation {
        &self.operations[index]
    }
}

impl Operation {
    pub(crate) fn encode_fixed(&self, values: &GreaseValues, output: &mut Vec<u8>) -> bool {
        let Self::Fixed { bytes, grease } = self else {
            return false;
        };
        let start = output.len();
        output.extend_from_slice(bytes);
        #[cfg(test)]
        crate::handshake::config_measurement::copied(
            crate::handshake::config_measurement::CopySite::FixedExtension,
            bytes.len(),
        );
        if let Some((offset, index)) = grease {
            output[start + offset..start + offset + 2]
                .copy_from_slice(&values.get(*index).to_be_bytes());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompileOptions, CompiledClientConfig, Transport};
    use crate::crypto::kx::{generate_key_pair, KxGroup};
    use crate::profile::types::{EchMode, ExtensionSpec};

    #[test]
    fn compiled_and_interpreted_encoders_match_with_grease_and_static_payloads() {
        for mut profile in [
            crate::profile::presets::chrome_155(),
            crate::profile::presets::firefox_156(),
        ] {
            profile.randomization = None;
            profile.ech = Some(EchMode::Disabled);
            profile.grease.signature_algorithms = true;
            profile.extensions.push(ExtensionSpec {
                extension_type: ext_type::TRUST_ANCHOR_IDS,
                source: ExtensionSource::TrustAnchorIds {
                    ids: vec!["0102".into()],
                    shuffle: false,
                },
            });
            let base = CompiledClientConfig::compile(
                profile,
                Transport::Tcp,
                CompileOptions::compatibility(),
            )
            .unwrap();
            let grease = GreaseValues::new();
            let keys = [generate_key_pair(KxGroup::X25519).unwrap()];
            let build = |compiled| {
                ClientHelloBuilder::new(&base.hello_profile, "localhost")
                    .with_compiled(compiled)
                    .with_grease_values(grease.clone())
                    .with_random([7; 32])
                    .with_session_id(vec![9; 32])
                    .build_with_key_pairs(&keys)
                    .unwrap()
                    .message
            };
            assert_eq!(build(Some(&base)), build(None));
            assert!(base.encoding.operations.len() > 8);
        }
    }

    #[test]
    fn duplicate_extension_occurrences_keep_independent_payloads() {
        use rand_core::SeedableRng;
        let mut profile = crate::profile::presets::chrome_155();
        profile.ech = Some(EchMode::Disabled);
        for data in ["010203", "040506", "010203"] {
            profile.extensions.push(ExtensionSpec {
                extension_type: 0xeeff,
                source: ExtensionSource::RawBytes { data: data.into() },
            });
        }
        let base =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        let grease = GreaseValues::new();
        let keys = [generate_key_pair(KxGroup::X25519).unwrap()];
        for seed in [3, 7, 11] {
            let build = |compiled| {
                ClientHelloBuilder::new(&base.hello_profile, "localhost")
                    .with_compiled(compiled)
                    .with_rng(rand_chacha::ChaCha20Rng::from_seed([seed; 32]))
                    .with_grease_values(grease.clone())
                    .with_random([7; 32])
                    .with_session_id(vec![9; 32])
                    .build_with_key_pairs(&keys)
                    .unwrap()
                    .message
            };
            let message = build(Some(&base));
            assert_eq!(message, build(None));
            let wire =
                crate::handshake::client_hello_wire::ClientHelloWire::parse(&message).unwrap();
            let mut payloads: Vec<_> = wire
                .extensions
                .iter()
                .filter(|e| e.extension_type == 0xeeff)
                .map(|e| wire.handshake[e.payload.clone()].to_vec())
                .collect();
            payloads.sort();
            assert_eq!(payloads, [vec![1, 2, 3], vec![1, 2, 3], vec![4, 5, 6]]);
        }
    }
}
