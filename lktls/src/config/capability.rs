//! Versioned capability admission, separate from configuration lifetime.

use super::{
    Admission, CapabilityIssue, CapabilityKind, CapabilityReason, CompileError, CompileOptions,
    SecurityPolicy, Transport,
};
use crate::crypto::{
    kx::KxGroup,
    suites::{tls12_suite, tls13_suite},
};
use crate::handshake::client_hello_wire::is_grease;
use crate::profile::types::{ext_type, ExtensionSource, TlsProfile};
use crate::verify::signature::{supports, SignaturePurpose};
use std::{collections::BTreeMap, sync::Arc};

fn vector16(payload: &[u8], prefix: usize) -> Result<Vec<u16>, CompileError> {
    let length = match prefix {
        1 => payload.first().copied().map(usize::from),
        2 => payload
            .get(..2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]) as usize),
        _ => unreachable!(),
    }
    .ok_or_else(|| CompileError::Invalid("truncated capability vector".into()))?;
    if length == 0 || length % 2 != 0 || payload.len() != prefix + length {
        return Err(CompileError::Invalid(
            "invalid capability vector length".into(),
        ));
    }
    Ok(payload[prefix..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_be_bytes([v[0], v[1]]))
        .collect())
}

pub(super) fn capability_issues(
    profile: &TlsProfile,
    transport: Transport,
    options: &CompileOptions,
    decoded: &BTreeMap<String, Arc<[u8]>>,
) -> Result<Vec<CapabilityIssue>, CompileError> {
    let strict = options.admission == Admission::Complete;
    if strict
        && (profile.session_id_length > 32
            || profile.compression_methods != [0]
            || profile.cipher_suites.is_empty()
            || profile.cipher_suites.len() > 32767)
    {
        return Err(CompileError::Invalid(
            "invalid session id, compression methods or cipher vector".into(),
        ));
    }
    let has = |code| {
        profile
            .extensions
            .iter()
            .any(|e| e.extension_type == code && !matches!(e.source, ExtensionSource::Grease))
    };
    let mut groups = if has(ext_type::SUPPORTED_GROUPS) {
        profile.supported_groups.clone()
    } else {
        Vec::new()
    };
    let mut signatures = if has(ext_type::SIGNATURE_ALGORITHMS) {
        profile.signature_algorithms.clone()
    } else {
        Vec::new()
    };
    let mut compression = if has(ext_type::COMPRESS_CERTIFICATE) {
        profile.compress_cert_algorithms.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut versions = Vec::new();
    let mut extension_issues = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for extension in &profile.extensions {
        if matches!(extension.source, ExtensionSource::Grease)
            || is_grease(extension.extension_type)
        {
            continue;
        }
        if strict && !seen.insert(extension.extension_type) {
            return Err(CompileError::Invalid(format!(
                "duplicate extension 0x{:04x}",
                extension.extension_type
            )));
        }
        if let ExtensionSource::RawBytes { data } = &extension.source {
            if strict {
                crate::extensions::registry::validate_client_payload(
                    extension.extension_type,
                    &decoded[data],
                )
                .map_err(|e| CompileError::Invalid(e.to_string()))?;
            }
            let result = match extension.extension_type {
                ext_type::SUPPORTED_GROUPS => vector16(&decoded[data], 2).map(|v| groups = v),
                ext_type::SIGNATURE_ALGORITHMS => {
                    vector16(&decoded[data], 2).map(|v| signatures = v)
                }
                ext_type::SUPPORTED_VERSIONS => vector16(&decoded[data], 1).map(|v| versions = v),
                ext_type::COMPRESS_CERTIFICATE => {
                    vector16(&decoded[data], 1).map(|v| compression = v)
                }
                _ => Ok(()),
            };
            if strict {
                result?;
            }
            if strict {
                match extension.extension_type {
                    ext_type::ALPN
                    | ext_type::APPLICATION_SETTINGS
                    | ext_type::APPLICATION_SETTINGS_NEW => {
                        let protocols =
                            crate::extensions::alpn::parse_alpn_list_bytes(&decoded[data])
                                .ok_or_else(|| {
                                    CompileError::Invalid("invalid raw protocol list".into())
                                })?;
                        let expected = if extension.extension_type == ext_type::ALPN {
                            &profile.alpn_protocols[..]
                        } else {
                            profile.alps_protocols.as_deref().unwrap_or_default()
                        };
                        if !protocols
                            .iter()
                            .copied()
                            .eq(expected.iter().map(|p| p.as_bytes()))
                        {
                            return Err(CompileError::Invalid(
                                "raw protocol list conflicts with profile".into(),
                            ));
                        }
                    }
                    ext_type::RECORD_SIZE_LIMIT => {
                        let limit =
                            crate::extensions::record_size_limit::parse_peer_record_size_limit(
                                &decoded[data],
                            )
                            .map_err(|e| CompileError::Invalid(e.to_string()))?;
                        if profile.record_size_limit != Some(limit) {
                            return Err(CompileError::Invalid(
                                "raw record limit conflicts with profile".into(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            if matches!(
                extension.extension_type,
                ext_type::KEY_SHARE
                    | ext_type::PRE_SHARED_KEY
                    | ext_type::PSK_KEY_EXCHANGE_MODES
                    | ext_type::EARLY_DATA
                    | ext_type::ENCRYPTED_CLIENT_HELLO
                    | ext_type::QUIC_TRANSPORT_PARAMETERS
            ) {
                extension_issues.push(extension.extension_type);
            }
        }
        // Advertising these permits peer behaviors not yet implemented.
        if !matches!(
            extension.extension_type,
            0 | 5
                | 10
                | 11
                | 13
                | 16
                | 18
                | 21
                | 22
                | 23
                | 27
                | 28
                | 35
                | 41
                | 42
                | 43
                | 44
                | 45
                | 51
                | 57
                | 0x4469
                | 0x44cd
                | 0xca34
                | 0xfe0d
                | 0xff01
        ) {
            extension_issues.push(extension.extension_type);
        }
    }
    if versions.is_empty() {
        for version in 0x0301..=0x0304 {
            if version >= profile.tls_min_version.as_u16()
                && version <= profile.tls_max_version.as_u16()
            {
                versions.push(version);
            }
        }
    }
    if strict {
        if !versions.iter().any(|v| matches!(v, 0x0303 | 0x0304)) {
            return Err(CompileError::Invalid("no executable TLS version".into()));
        }
        let same = |a: &[u16], b: &[u16]| {
            a.iter()
                .filter(|v| !is_grease(**v))
                .eq(b.iter().filter(|v| !is_grease(**v)))
        };
        if (has(ext_type::SUPPORTED_GROUPS) && !same(&groups, &profile.supported_groups))
            || (has(ext_type::SIGNATURE_ALGORITHMS)
                && !same(&signatures, &profile.signature_algorithms))
            || (has(ext_type::COMPRESS_CERTIFICATE)
                && compression != profile.compress_cert_algorithms.clone().unwrap_or_default())
            || versions.iter().any(|v| {
                !is_grease(*v)
                    && (*v < profile.tls_min_version.as_u16()
                        || *v > profile.tls_max_version.as_u16())
            })
        {
            return Err(CompileError::Invalid(
                "raw capability payload conflicts with profile semantics".into(),
            ));
        }
        if versions.contains(&0x0304)
            && (!has(ext_type::SUPPORTED_VERSIONS)
                || !has(ext_type::KEY_SHARE)
                || groups.is_empty()
                || signatures.is_empty()
                || profile.key_share_curves.iter().any(|g| !groups.contains(g)))
        {
            return Err(CompileError::Invalid(
                "TLS 1.3 requires supported versions, groups, signatures and matching key shares"
                    .into(),
            ));
        }
        if versions.contains(&0x0303)
            && profile.cipher_suites.iter().any(|s| {
                tls12_suite(*s).is_some_and(|s| {
                    s.key_exchange() != crate::crypto::tls12_cipher::Tls12KeyExchange::Rsa
                })
            })
            && (groups.is_empty() || signatures.is_empty())
        {
            return Err(CompileError::Invalid(
                "TLS 1.2 ECDHE requires explicit groups and signatures".into(),
            ));
        }
        for &version in &versions {
            if matches!(version, 0x0303 | 0x0304)
                && !profile.cipher_suites.iter().any(|s| {
                    if version == 0x0304 {
                        tls13_suite(*s).is_some()
                    } else {
                        tls12_suite(*s).is_some()
                    }
                })
            {
                return Err(CompileError::Invalid(format!(
                    "no executable cipher suite for version 0x{version:04x}"
                )));
            }
        }
        if !profile
            .alpn_protocols
            .iter()
            .chain(profile.alps_protocols.iter().flatten())
            .all(|p| !p.is_empty() && p.len() <= 255)
        {
            return Err(CompileError::Invalid(
                "ALPN/ALPS protocol length must be 1..=255".into(),
            ));
        }
        if profile
            .record_size_limit
            .is_some_and(|v| !(64..=16385).contains(&v))
        {
            return Err(CompileError::Invalid(
                "record size limit must be 64..=16385".into(),
            ));
        }
    }
    let mut issues = Vec::new();
    let mut add = |kind, code, version, reason| {
        let issue = CapabilityIssue {
            kind,
            code,
            version,
            reason,
        };
        if !issues.contains(&issue) {
            issues.push(issue);
        }
    };
    for &version in &versions {
        if is_grease(version) {
            continue;
        }
        if !matches!(version, 0x0303 | 0x0304)
            || (transport == Transport::Quic && version != 0x0304)
        {
            add(
                CapabilityKind::Version,
                version,
                Some(version),
                CapabilityReason::MissingImplementation,
            );
        }
        if options.security == SecurityPolicy::Modern && version < 0x0303 {
            add(
                CapabilityKind::Version,
                version,
                Some(version),
                CapabilityReason::ProhibitedByPolicy,
            );
        }
    }
    for &suite in &profile.cipher_suites {
        if is_grease(suite) || matches!(suite, 0x00ff | 0x5600) {
            continue;
        }
        if tls12_suite(suite).is_none() && tls13_suite(suite).is_none() {
            add(
                CapabilityKind::CipherSuite,
                suite,
                None,
                CapabilityReason::MissingImplementation,
            );
            continue;
        }
        let version = if tls13_suite(suite).is_some() {
            0x0304
        } else {
            0x0303
        };
        if !versions.contains(&version) {
            continue;
        }
        if options.security == SecurityPolicy::Modern
            && version == 0x0303
            && tls12_suite(suite).is_some_and(|suite| {
                !suite.is_aead()
                    || suite.key_exchange() == crate::crypto::tls12_cipher::Tls12KeyExchange::Rsa
            })
        {
            add(
                CapabilityKind::CipherSuite,
                suite,
                Some(version),
                CapabilityReason::ProhibitedByPolicy,
            );
        }
    }
    for group in groups
        .into_iter()
        .chain(profile.key_share_curves.iter().copied())
    {
        if !is_grease(group) && KxGroup::from_code_point(group).is_none() {
            add(
                CapabilityKind::KeyExchangeGroup,
                group,
                None,
                CapabilityReason::MissingImplementation,
            );
        }
    }
    for scheme in signatures {
        if is_grease(scheme) {
            continue;
        }
        for (version, purpose) in [
            (0x0303, SignaturePurpose::Tls12ServerKeyExchange),
            (0x0304, SignaturePurpose::Tls13CertificateVerify),
        ] {
            if !versions.contains(&version) {
                continue;
            }
            // PKCS#1/SHA-1 in a TLS 1.3 offer constrain certificate signatures,
            // not CertificateVerify. Their chain purpose is owned by webpki.
            if version == 0x0304 && matches!(scheme, 0x0201 | 0x0203 | 0x0401 | 0x0501 | 0x0601) {
                continue;
            }
            if !supports(purpose, scheme) {
                add(
                    CapabilityKind::Signature,
                    scheme,
                    Some(version),
                    CapabilityReason::MissingImplementation,
                );
            }
        }
    }
    if versions.contains(&0x0304) {
        for algorithm in compression {
            if !matches!(algorithm, 1..=3) {
                add(
                    CapabilityKind::CertificateCompression,
                    algorithm,
                    Some(0x0304),
                    CapabilityReason::MissingImplementation,
                );
            }
        }
    }
    for extension in extension_issues {
        let version = match extension {
            ext_type::ENCRYPT_THEN_MAC => {
                if !versions.contains(&0x0303)
                    || !profile
                        .cipher_suites
                        .iter()
                        .any(|s| tls12_suite(*s).is_some_and(|s| !s.is_aead()))
                {
                    continue;
                }
                Some(0x0303)
            }
            ext_type::DELEGATED_CREDENTIALS => {
                if !versions.contains(&0x0304) {
                    continue;
                }
                Some(0x0304)
            }
            _ => None,
        };
        add(
            CapabilityKind::Extension,
            extension,
            version,
            CapabilityReason::MissingImplementation,
        );
    }
    Ok(issues)
}
