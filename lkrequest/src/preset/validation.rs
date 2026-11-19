use std::collections::HashSet;

use lktls::profile::types::{EchMode, ExtensionSource, PaddingStrategy, TlsProfile, TlsVersion};

use super::document::{PresetError, PresetLimits};
use super::ClientPreset;

pub(super) fn validate(preset: &ClientPreset, limits: &PresetLimits) -> Result<(), PresetError> {
    validate_effective(
        &preset.tls_profile,
        preset.quic_tls_profile.as_ref(),
        &preset.h2_profile,
        preset.quic_profile.as_ref(),
        &preset.default_protocol_policy.clone().unwrap_or_default(),
        limits,
    )?;
    for (path, headers) in [
        ("/header_order", Some(&preset.header_order)),
        ("/h3_header_order", preset.h3_header_order.as_ref()),
    ] {
        if let Some(headers) = headers {
            let mut seen = HashSet::new();
            for h in headers {
                if !seen.insert(h) {
                    return Err(PresetError::invalid(path, "duplicate header name"));
                }
            }
        }
    }
    if let Some(cookies) = &preset.cookie_order {
        let mut seen = HashSet::new();
        for (i, name) in cookies.iter().enumerate() {
            if name.is_empty() || !name.bytes().all(token) || !seen.insert(name) {
                return Err(PresetError::invalid(
                    format!("/cookie_order/{i}"),
                    "invalid or duplicate cookie name",
                ));
            }
        }
    }
    Ok(())
}

fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub(crate) fn validate_effective(
    tls: &TlsProfile,
    quic_tls: Option<&TlsProfile>,
    h2: &lkh2::profile::H2Profile,
    quic: Option<&crate::QuicProfile>,
    policy: &crate::protocol::ProtocolPolicy,
    limits: &PresetLimits,
) -> Result<(), PresetError> {
    let mut opaque = 0;
    validate_tls(tls, "/tls_profile", &mut opaque)?;
    if let Some(profile) = quic_tls {
        validate_tls(profile, "/quic_tls_profile", &mut opaque)?;
    }
    if opaque > limits.max_opaque_bytes {
        return Err(PresetError::limit(
            "/",
            "total opaque TLS payload limit exceeded",
        ));
    }
    lkh2::synthesis::validate(h2)
        .map_err(|e| PresetError::invalid("/h2_profile", e.to_string()))?;
    if h2.priority_config.default_urgency > 7 {
        return Err(PresetError::invalid(
            "/h2_profile/priority_config/default_urgency",
            "urgency must be in 0..7",
        ));
    }
    if h2.initial_stream_id == 0
        || h2.initial_stream_id > 0x7fff_ffff
        || h2.initial_stream_id.is_multiple_of(2)
    {
        return Err(PresetError::invalid(
            "/h2_profile/initial_stream_id",
            "client stream ID must be an odd, nonzero 31-bit integer",
        ));
    }
    if let Some(p) = &h2.headers_priority {
        if p.stream_dependency > 0x7fff_ffff || p.stream_dependency == h2.initial_stream_id {
            return Err(PresetError::invalid(
                "/h2_profile/headers_priority",
                "invalid or self-dependent priority",
            ));
        }
    }
    for p in &h2.priority_frames {
        if p.stream_id == 0
            || p.stream_id > 0x7fff_ffff
            || p.dependency > 0x7fff_ffff
            || p.stream_id == p.dependency
        {
            return Err(PresetError::invalid(
                "/h2_profile/priority_frames",
                "invalid or self-dependent priority frame",
            ));
        }
    }
    for setting in &h2.settings {
        if matches!(setting.id.as_u16(), 8 | 9) && setting.value > 1 {
            return Err(PresetError::invalid(
                "/h2_profile/settings",
                "boolean SETTINGS value must be 0 or 1",
            ));
        }
    }
    if let Some(config) = h2
        .behavior
        .as_ref()
        .and_then(|b| lkh2::policy::H2BehaviorConfig::from_behavior(b).ok())
    {
        config
            .build()
            .map_err(|e| PresetError::invalid("/runtime/h2_behavior", e))?;
    }
    policy
        .validate()
        .map_err(|e| PresetError::invalid("/runtime/protocol", e.to_string()))?;
    if quic.is_none()
        && (matches!(policy.intent, crate::protocol::HttpIntent::H3Only)
            || matches!(&policy.acquisition, crate::protocol::AcquisitionPolicy::Race(r) if r.enable_quic && !r.enable_tcp))
    {
        return Err(PresetError::invalid(
            "/runtime/protocol",
            "policy requires a QUIC/H3 profile",
        ));
    }
    if quic.is_some() && quic_tls.unwrap_or(tls).tls_max_version != TlsVersion::Tls13 {
        return Err(PresetError::invalid(
            "/quic_tls_profile",
            "QUIC requires TLS 1.3",
        ));
    }
    #[cfg(feature = "quic-h3")]
    if let Some(profile) = quic {
        profile
            .validate()
            .map_err(|e| PresetError::invalid("/quic_profile", e))?;
        for required in [
            lkh3::PseudoHeaderId::Method,
            lkh3::PseudoHeaderId::Authority,
            lkh3::PseudoHeaderId::Scheme,
            lkh3::PseudoHeaderId::Path,
        ] {
            if !profile.h3.pseudo_header_order.contains(&required) {
                return Err(PresetError::invalid(
                    "/quic_profile/h3/pseudo_header_order",
                    "ordinary request pseudo-headers must each be present",
                ));
            }
        }
        let mut value = serde_json::to_value(profile)
            .map_err(|_| PresetError::invalid("/quic_profile", "cannot serialize QUIC profile"))?;
        super::quic_json::convert(&mut value, true)?;
        if profile.transport_params.initial_max_streams_bidi > (1_u64 << 60)
            || profile.transport_params.initial_max_streams_uni > (1_u64 << 60)
        {
            return Err(PresetError::invalid(
                "/quic_profile/transport_params",
                "stream count exceeds QUIC's 2^60 limit",
            ));
        }
        if let Some(layout) = &profile.packetization.initial_frame_layout {
            for packet in &layout.packets {
                if packet.packet_number > u32::MAX as u64 {
                    return Err(PresetError::invalid(
                        "/quic_profile/packetization/initial_frame_layout",
                        "Initial packet number exceeds supported 32-bit encoding",
                    ));
                }
                let mut length = 0_usize;
                for frame in &packet.frames {
                    let n = match frame {
                        lkh3::InitialFrameElement::Crypto { offset, length } => {
                            if offset
                                .checked_add(*length as u64)
                                .is_none_or(|end| end >= (1_u64 << 62))
                            {
                                return Err(PresetError::invalid(
                                    "/quic_profile/packetization/initial_frame_layout",
                                    "CRYPTO range exceeds QUIC integer bounds",
                                ));
                            }
                            *length
                        }
                        lkh3::InitialFrameElement::Padding { length } => *length,
                        lkh3::InitialFrameElement::Ping => 1,
                    };
                    length = length.checked_add(n).ok_or_else(|| {
                        PresetError::limit(
                            "/quic_profile/packetization/initial_frame_layout",
                            "frame lengths overflow",
                        )
                    })?;
                }
                if length > layout.target_udp_payload_size as usize {
                    return Err(PresetError::invalid(
                        "/quic_profile/packetization/initial_frame_layout",
                        "frame data exceeds the target datagram",
                    ));
                }
            }
        }
        if profile.h3.qpack_max_table_capacity > 16 * 1024 * 1024
            || profile.h3.qpack_blocked_streams > 65_536
        {
            return Err(PresetError::limit(
                "/quic_profile/h3",
                "QPACK resource limit exceeded",
            ));
        }
        let mut settings = HashSet::new();
        for &(id, value) in &profile.h3.settings {
            if !settings.insert(id) {
                return Err(PresetError::invalid(
                    "/quic_profile/h3/settings",
                    "duplicate SETTINGS identifier",
                ));
            }
            let expected = match id {
                1 => Some(profile.h3.qpack_max_table_capacity),
                7 => Some(profile.h3.qpack_blocked_streams),
                6 => profile.h3.max_field_section_size,
                _ => None,
            };
            if expected.is_some_and(|v| v != value) {
                return Err(PresetError::invalid(
                    "/quic_profile/h3/settings",
                    "SETTINGS conflicts with the corresponding explicit H3 field",
                ));
            }
        }
        for (_, hex) in &profile.transport_params.extra_transport_parameters {
            opaque += hex_bytes(
                hex,
                "/quic_profile/transport_params/extra_transport_parameters",
                65535,
            )?;
        }
        if opaque > limits.max_opaque_bytes {
            return Err(PresetError::limit(
                "/",
                "total opaque payload limit exceeded",
            ));
        }
    }
    Ok(())
}

fn validate_tls(profile: &TlsProfile, path: &str, opaque: &mut usize) -> Result<(), PresetError> {
    lktls::profile::validate(profile).map_err(|e| PresetError::invalid(path, e.to_string()))?;
    let mut shares = HashSet::new();
    if profile.key_share_curves.iter().any(|id| !shares.insert(id)) {
        return Err(PresetError::invalid(
            format!("{path}/key_share_curves"),
            "duplicate key share",
        ));
    }
    if profile.cipher_suites.len() > 32767
        || profile.supported_groups.len() > 32767
        || profile.signature_algorithms.len() > 32767
        || profile
            .compress_cert_algorithms
            .as_ref()
            .is_some_and(|v| v.len() > 127)
    {
        return Err(PresetError::invalid(
            path,
            "TLS vector length exceeds its wire encoding",
        ));
    }
    if profile.session_id_length > 32 {
        return Err(PresetError::invalid(
            format!("{path}/session_id_length"),
            "session ID exceeds 32 bytes",
        ));
    }
    if profile.compression_methods.is_empty()
        || profile.compression_methods.len() > 255
        || profile.ec_point_formats.len() > 255
    {
        return Err(PresetError::invalid(path, "invalid u8-length TLS vector"));
    }
    let mut alpn_bytes = 2;
    for protocol in profile
        .alpn_protocols
        .iter()
        .chain(profile.alps_protocols.iter().flatten())
    {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(PresetError::invalid(
                format!("{path}/alpn_protocols"),
                "protocol IDs must contain 1..255 bytes",
            ));
        }
        alpn_bytes += protocol.len() + 1;
    }
    if alpn_bytes > 65535 {
        return Err(PresetError::invalid(
            path,
            "ALPN/ALPS vector exceeds TLS length limits",
        ));
    }
    if let PaddingStrategy::BlockAlign { block_size: 0, .. } = profile.padding {
        return Err(PresetError::invalid(
            format!("{path}/padding/block_size"),
            "padding block size must be positive",
        ));
    }
    let mut raw_total = 0;
    for (i, ext) in profile.extensions.iter().enumerate() {
        let source_path = format!("{path}/extensions/{i}/source");
        match &ext.source {
            ExtensionSource::RawBytes { data } => {
                let n = hex_bytes(data, &source_path, 65535)?;
                *opaque += n;
                raw_total += n + 4;
            }
            ExtensionSource::TrustAnchorIds { ids, .. } => {
                let mut total = 0;
                for id in ids {
                    let n = hex_bytes(id, &source_path, 255)?;
                    if n == 0 {
                        return Err(PresetError::invalid(
                            &source_path,
                            "trust-anchor ID cannot be empty",
                        ));
                    }
                    total += n + 1;
                    *opaque += n;
                }
                if total > 65533 {
                    return Err(PresetError::invalid(
                        &source_path,
                        "trust-anchor vector exceeds TLS length limit",
                    ));
                }
                raw_total += total + 6;
            }
            _ => raw_total += 4,
        }
    }
    if raw_total > 65535 {
        return Err(PresetError::invalid(
            format!("{path}/extensions"),
            "extension vector exceeds TLS length limit",
        ));
    }
    if let Some(EchMode::Grease(config)) = &profile.ech {
        if config
            .payload_length_min
            .zip(config.payload_length_max)
            .is_some_and(|(min, max)| min > max)
            || config.enc_length as usize
                + config
                    .payload_length_max
                    .unwrap_or(config.payload_length_min.unwrap_or(256).max(256))
                    as usize
                + 10
                > 65535
        {
            return Err(PresetError::invalid(
                format!("{path}/ech"),
                "invalid ECH GREASE payload bounds",
            ));
        }
    }
    if let Some(EchMode::Real { ech_config_list }) = &profile.ech {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ech_config_list)
            .map_err(|_| {
                PresetError::invalid(format!("{path}/ech"), "invalid base64 ECHConfigList")
            })?;
        if bytes.len() < 2
            || bytes.len() > 65535
            || u16::from_be_bytes([bytes[0], bytes[1]]) as usize != bytes.len() - 2
        {
            return Err(PresetError::invalid(
                format!("{path}/ech"),
                "invalid ECHConfigList length",
            ));
        }
        *opaque += bytes.len();
        let configs = lktls::ech::config::parse_ech_config_list(&bytes)
            .map_err(|e| PresetError::invalid(format!("{path}/ech"), e.to_string()))?;
        if configs.is_empty() {
            return Err(PresetError::invalid(
                format!("{path}/ech"),
                "ECHConfigList has no supported configuration",
            ));
        }
    }
    Ok(())
}

fn hex_bytes(hex: &str, path: &str, max: usize) -> Result<usize, PresetError> {
    if !hex.len().is_multiple_of(2)
        || hex.len() / 2 > max
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(PresetError::invalid(
            path,
            "invalid or oversized hex payload",
        ));
    }
    Ok(hex.len() / 2)
}
