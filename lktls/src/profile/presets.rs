//! Built-in fingerprint profiles for common clients.
//!
//! These are convenience constructors that return pre-configured [`TlsProfile`]
//! instances.
//!
//! ## Verification status
//!
//! | Profile | Status | Reference data | JA3/JA4 test |
//! |---------|--------|----------------|--------------|
//! | [`chrome_144`] | **Verified** | tls.browserleaks.com live verification | `e2e_fingerprint.rs` |
//! | [`chrome_145`] | **Verified (capture)** | `profile-collector` real Chrome 145 capture | none |
//! | [`chrome_147`] | **Verified (capture)** | `profile-collector` real Chrome 147 capture | none |
//! | [`chrome_148`] | **Verified (capture)** | `profile-collector` real Chrome 148 capture | none |
//! | [`firefox_147`] | **Verified** | `tlsleak/firefox147.0.3_tlsleak.json` | `e2e_firefox_fingerprint.rs` |
//! | [`firefox_156`] | **Verified (capture)** | public Cloudflare Wireshark capture | `fingerprint_regression.rs` |
//! | [`safari_26`] | **Verified** | `tlsleak/safari26.2_tlsleak.json` | `e2e_safari_fingerprint.rs` |
//! | [`chrome_131`] | **Unverified** | no reference data | none |
//! | [`firefox_133`] | **Unverified** | no reference data | none |
//! | [`safari_18`] | **Unverified** | no reference data | none |
//!
//! **For production use, prefer the verified profiles (chrome_155 / firefox_156 / safari_26).**
//! Unverified profiles may have subtle deviations in extension order, parameter values, etc.,
//! which risk detection in adversarial scenarios.

use super::types::*;

/// Load the built-in Chrome 131 profile.
///
/// **Unverified** — lacks real browser reference data and has not undergone JA3/JA4 consistency testing.
/// Hand-built from example.com / Wireshark captures, but the original reference data was not retained.
/// For production use, prefer the verified [`chrome_144`].
pub fn chrome_131() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_131.json");
    serde_json::from_str(json_str).expect("built-in chrome_131 profile should be valid")
}

/// Load the built-in Chrome 144 profile.
///
/// **Verified** — live-verified via tls.browserleaks.com JA3/JA4/Akamai H2 fingerprints.
/// Chrome 144 includes X25519MLKEM768 post-quantum key exchange and ECH.
pub fn chrome_144() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_144.json");
    serde_json::from_str(json_str).expect("built-in chrome_144 profile should be valid")
}

/// Load the built-in Chrome 145 profile.
///
/// **Verified (capture)** — the TLS extension order and ECH GREASE ranges come from a `profile-collector` capture.
/// The experimental / Finch-gated features carried by the captured build (opaque ext `51764`/`0xca34`, H2 SETTINGS id
/// `6746`) are field-trial-variable and are not sent by stable 148. To keep the versions consistent, they are
/// uniformly excluded under the default "experiment off" state.
pub fn chrome_145() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_145.json");
    serde_json::from_str(json_str).expect("built-in chrome_145 profile should be valid")
}

/// Load the built-in Chrome 146 profile.
///
/// **Verified** — captured from a real Chrome 146 browser and verified via profile-collector.
/// The TLS fingerprint matches Chrome 144 (same cipher suites, extensions, groups, algorithms),
/// using the extension order actually captured from Chrome 146. The H2 fingerprint is also identical to Chrome 144.
pub fn chrome_146() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_146.json");
    serde_json::from_str(json_str).expect("built-in chrome_146 profile should be valid")
}

/// Chrome 146 QUIC ClientHello profile.
///
/// This is calibrated from the observed HTTP/3 capture rather than the TCP/H2
/// profile. QUIC uses TLS 1.3 only, an empty legacy session id, ALPN `h3`, and
/// carries QUIC transport parameters in extension `0x0039`.
fn chromium_quic_profile(mut profile: TlsProfile, name: &str) -> TlsProfile {
    let trust_anchor_ids = profile
        .extensions
        .iter()
        .find(|extension| extension.extension_type == ext_type::TRUST_ANCHOR_IDS)
        .cloned();
    profile.name = name.to_string();
    profile.tls_min_version = TlsVersion::Tls13;
    profile.tls_max_version = TlsVersion::Tls13;
    // QUIC mandates TLS 1.3, so the ClientHello offers ONLY the three TLS 1.3
    // cipher suites (real Chrome's QUIC ja4 is `q13d03…` — 3 ciphers). The TCP
    // profile's list (which includes TLS 1.2 suites) must NOT leak in here.
    profile.cipher_suites = vec![0x1301, 0x1302, 0x1303];
    // Chrome's QUIC ClientHello appends rsa_pkcs1_sha1 (0x0201) to the TCP
    // signature_algorithms list — observed in real Chrome's QUIC JA4
    // (`…,0601,0201`); its TCP ClientHello omits it.
    profile.signature_algorithms.push(0x0201);
    profile.session_id_length = 0;
    profile.alpn_protocols = vec!["h3".to_string()];
    profile.alps_protocols = Some(vec!["h3".to_string()]);
    profile.randomization = None;
    profile.extensions = [
        ext_type::PSK_KEY_EXCHANGE_MODES,
        ext_type::SUPPORTED_GROUPS,
        ext_type::KEY_SHARE,
        ext_type::ENCRYPTED_CLIENT_HELLO,
        ext_type::ALPN,
        ext_type::SNI,
        ext_type::COMPRESS_CERTIFICATE,
        ext_type::SIGNATURE_ALGORITHMS,
        ext_type::EARLY_DATA,
        ext_type::SUPPORTED_VERSIONS,
        ext_type::QUIC_TRANSPORT_PARAMETERS,
        ext_type::APPLICATION_SETTINGS_NEW,
    ]
    .into_iter()
    .map(|extension_type| ExtensionSpec {
        extension_type,
        source: ExtensionSource::Auto,
    })
    .collect();
    if let Some(trust_anchor_ids) = trust_anchor_ids {
        profile.extensions.push(trust_anchor_ids);
    }
    profile
}

pub fn chrome_146_quic() -> TlsProfile {
    chromium_quic_profile(chrome_146(), "Chrome 146 QUIC")
}

/// Load the built-in Chrome 147 profile.
///
/// **Verified (capture)** — the extension order and ECH GREASE payload ranges come from a real Chrome 147
/// `profile-collector` capture; cipher/groups/H2 match Chrome 144/146.
pub fn chrome_147() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_147.json");
    serde_json::from_str(json_str).expect("built-in chrome_147 profile should be valid")
}

/// Load the built-in Chrome 148 profile.
///
/// **Verified (capture)** — the extension order and ECH GREASE payload ranges come from a real Chrome 148
/// `profile-collector` capture; cipher/groups/ALPN/ALPS match Chrome 144/146/147.
/// The captured `pre_shared_key` is not hardcoded in the profile; it is generated dynamically by lktls session resumption logic.
pub fn chrome_148() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_148.json");
    serde_json::from_str(json_str).expect("built-in chrome_148 profile should be valid")
}

/// Load the built-in Chrome 149 profile.
///
/// **Verified (capture)** — capturing real Chrome 149.0.7827.54 via `profile-collector`
/// and diffing showed the network fingerprint is byte-identical to Chrome 148
/// (cipher suites, groups incl. X25519MlKem768, signature algorithms, ALPN/ALPS,
/// ECH, and H2/Akamai all match; only per-connection extension-order shuffle and
/// random GREASE differ). The profile mirrors Chrome 148 accordingly.
pub fn chrome_149() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_149.json");
    serde_json::from_str(json_str).expect("built-in chrome_149 profile should be valid")
}

/// Load the built-in Chrome 150 profile.
///
/// **Verified (capture)** — captured from real Chrome 150.0.7871.47 via
/// `profile-collector`. The only wire change vs Chrome 149 is `signature_algorithms`:
/// Chrome 150 prepends three ML-DSA post-quantum codepoints `0x0904`/`0x0905`/`0x0906`
/// (2308/2309/2310) ahead of the classic eight. Everything else matches 149 — cipher
/// suites, groups (incl. X25519MlKem768), key_share, ALPN/ALPS, ECH, and H2/Akamai;
/// only per-connection extension-order shuffle and random GREASE otherwise differ.
/// This shifts JA4 (the sig-alg hash) but leaves JA3 unchanged.
pub fn chrome_150() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_150.json");
    serde_json::from_str(json_str).expect("built-in chrome_150 profile should be valid")
}

/// Chrome 150 QUIC ClientHello profile.
///
/// Uses Chrome 150's captured TLS capabilities, including the ML-DSA signature
/// algorithms, while applying Chromium's QUIC-only TLS 1.3 shape.
pub fn chrome_150_quic() -> TlsProfile {
    chromium_quic_profile(chrome_150(), "Chrome 150 QUIC")
}

/// Load the built-in Chrome 151 profile.
///
/// **Verified (capture)** — captured from real Chrome 151.0.7922.72 via
/// `profile-collector` on 2026-07-31. Stable TCP TLS and H2 fields are
/// unchanged from Chrome 150; only per-connection extension-order shuffle and
/// random GREASE differ.
pub fn chrome_151() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_151.json");
    serde_json::from_str(json_str).expect("built-in chrome_151 profile should be valid")
}

/// Chrome 151 QUIC ClientHello profile.
///
/// Verified across real QUIC connections to Cloudflare, Google, Slack, and
/// other public H3 origins. Unlike Chrome 151 TCP, QUIC omits the three ML-DSA
/// signature algorithms and keeps the classic list plus `rsa_pkcs1_sha1`.
pub fn chrome_151_quic() -> TlsProfile {
    let mut profile = chromium_quic_profile(chrome_151(), "Chrome 151 QUIC");
    profile
        .signature_algorithms
        .retain(|algorithm| !matches!(*algorithm, 0x0904..=0x0906));
    profile
}

/// Load the built-in Chrome 152 profile.
///
/// Captured from Chrome 152.0.7977.65 against public Cloudflare endpoints.
/// It adds the shuffled trust-anchor identifiers extension (`0xca34`) while
/// retaining Chrome 151's other stable TCP TLS fields.
pub fn chrome_152() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_152.json");
    serde_json::from_str(json_str).expect("built-in chrome_152 profile should be valid")
}

/// Chrome 152 QUIC ClientHello profile.
///
/// Public Cloudflare capture keeps Chrome 151's QUIC signature-algorithm shape
/// and carries the same trust-anchor identifier set as TCP TLS.
pub fn chrome_152_quic() -> TlsProfile {
    let mut profile = chromium_quic_profile(chrome_152(), "Chrome 152 QUIC");
    profile.grease.signature_algorithms = false;
    profile
        .signature_algorithms
        .retain(|algorithm| !matches!(*algorithm, 0x0904..=0x0906));
    profile
}

/// Chrome 153.0.8010.37 TCP profile captured against public Cloudflare.
/// The trust-anchor identifier set contains 28 entries; other stable fields
/// retain Chrome 152's shape, including signature-algorithm GREASE.
pub fn chrome_153() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_153.json");
    serde_json::from_str(json_str).expect("built-in chrome_153 profile should be valid")
}

/// Chrome 153 QUIC ClientHello captured against Cloudflare and Google.
/// QUIC retains the classic signature algorithms without TCP's ML-DSA or TLS
/// GREASE slots, and advertises the same 28 trust-anchor identifiers as TCP.
pub fn chrome_153_quic() -> TlsProfile {
    let mut profile = chromium_quic_profile(chrome_153(), "Chrome 153 QUIC");
    profile.grease = GreaseConfig::default();
    profile.randomization = Some(RandomizationConfig {
        shuffle_extensions: true,
    });
    profile
        .signature_algorithms
        .retain(|algorithm| !matches!(*algorithm, 0x0904..=0x0906));
    profile
}

/// Chrome 154.0.8037.58 TCP profile captured against public Cloudflare.
/// Stable TLS fields and the 28-entry trust-anchor set match Chrome 153.
pub fn chrome_154() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_154.json");
    serde_json::from_str(json_str).expect("built-in chrome_154 profile should be valid")
}

/// Chrome 154 QUIC ClientHello captured against public Cloudflare.
/// It retains Chrome 153's classic nine signature algorithms, shuffled
/// extensions, 28 trust anchors, and lack of ordinary TLS GREASE slots.
pub fn chrome_154_quic() -> TlsProfile {
    let mut profile = chromium_quic_profile(chrome_154(), "Chrome 154 QUIC");
    profile.grease = GreaseConfig::default();
    profile.randomization = Some(RandomizationConfig {
        shuffle_extensions: true,
    });
    profile
        .signature_algorithms
        .retain(|algorithm| !matches!(*algorithm, 0x0904..=0x0906));
    profile
}

/// Chrome 155.0.8059.40 TCP profile captured against Cloudflare and example.com.
/// Stable fields, including the 28 trust anchors and sigalgs GREASE, match 154.
pub fn chrome_155() -> TlsProfile {
    let json_str = include_str!("../../profiles/chrome_155.json");
    serde_json::from_str(json_str).expect("built-in chrome_155 profile should be valid")
}

/// Chrome 155 QUIC ClientHello from successful public Cloudflare H3 captures.
/// QUIC uses classic signatures without TCP's ML-DSA and ordinary TLS GREASE.
pub fn chrome_155_quic() -> TlsProfile {
    let mut profile = chromium_quic_profile(chrome_155(), "Chrome 155 QUIC");
    profile.grease = GreaseConfig::default();
    profile.randomization = Some(RandomizationConfig {
        shuffle_extensions: true,
    });
    profile
        .signature_algorithms
        .retain(|algorithm| !matches!(*algorithm, 0x0904..=0x0906));
    profile
}

/// Load the built-in Firefox 133 profile.
///
/// **Unverified** — lacks real browser reference data and has not undergone JA3/JA4 consistency testing.
/// Built by inference from Firefox 133's publicly documented ClientHello structure.
/// For production use, prefer the verified [`firefox_147`].
pub fn firefox_133() -> TlsProfile {
    let json_str = include_str!("../../profiles/firefox_133.json");
    serde_json::from_str(json_str).expect("built-in firefox_133 profile should be valid")
}

/// Load the built-in Firefox 147 profile.
///
/// **Verified** — calibrated from `tlsleak/firefox147.0.3_tlsleak.json` (a real browser capture),
/// and end-to-end verified via `e2e_firefox_fingerprint.rs` to fully match the JA3/JA4/Akamai H2 hashes.
/// Firefox 147 adds X25519MLKEM768 key share, `compress_certificate` (zlib+brotli+zstd),
/// removes `encrypt_then_mac`, and updates `delegated_credentials` algorithm list.
pub fn firefox_147() -> TlsProfile {
    let json_str = include_str!("../../profiles/firefox_147.json");
    serde_json::from_str(json_str).expect("built-in firefox_147 profile should be valid")
}

/// Load the built-in Firefox 156 profile.
///
/// Captured from Firefox 156.0.1 on Windows against public Cloudflare. It
/// removes two ECDSA CBC suites and both FFDHE groups from Firefox 147 and uses
/// AES-128-GCM for its fixed-size ECH GREASE payload.
pub fn firefox_156() -> TlsProfile {
    let json_str = include_str!("../../profiles/firefox_156.json");
    serde_json::from_str(json_str).expect("built-in firefox_156 profile should be valid")
}

/// Load the built-in Safari 18 profile.
///
/// **Unverified** — lacks real browser reference data and has not undergone JA3/JA4 consistency testing.
/// Built by inference from Safari 18's publicly documented ClientHello structure.
/// For production use, prefer the verified [`safari_26`].
pub fn safari_18() -> TlsProfile {
    let json_str = include_str!("../../profiles/safari_18.json");
    serde_json::from_str(json_str).expect("built-in safari_18 profile should be valid")
}

/// Load the built-in Safari 26.2 profile.
///
/// **Verified** — calibrated from `tlsleak/safari26.2_tlsleak.json` (a real browser capture),
/// and end-to-end verified via `e2e_safari_fingerprint.rs` to fully match the JA3/JA4/Akamai H2 hashes.
/// Safari 26.2 adds X25519MLKEM768 key share, `compress_certificate` (zlib),
/// removes `session_ticket` extension, and uses updated cipher suite order
/// with 3DES suites.
pub fn safari_26() -> TlsProfile {
    let json_str = include_str!("../../profiles/safari_26.json");
    serde_json::from_str(json_str).expect("built-in safari_26 profile should be valid")
}

#[cfg(test)]
mod tests {
    use crate::profile::types::{EchMode, ExtensionSource, TlsClientHelloStyle};

    use super::*;

    #[test]
    fn builtin_profiles_have_tls_client_hello_styles() {
        for profile in [
            chrome_131(),
            chrome_144(),
            chrome_145(),
            chrome_146(),
            chrome_147(),
            chrome_148(),
            chrome_149(),
            chrome_150(),
            chrome_151(),
            chrome_152(),
            chrome_153(),
        ] {
            assert_eq!(
                profile.tls_client_hello_style,
                TlsClientHelloStyle::ChromiumBoringssl,
                "{} should use Chromium/BoringSSL style",
                profile.name
            );
        }

        for profile in [firefox_133(), firefox_147(), firefox_156()] {
            assert_eq!(
                profile.tls_client_hello_style,
                TlsClientHelloStyle::FirefoxNss,
                "{} should use Firefox/NSS style",
                profile.name
            );
        }

        for profile in [safari_18(), safari_26()] {
            assert_eq!(
                profile.tls_client_hello_style,
                TlsClientHelloStyle::SafariCfnetwork,
                "{} should use Safari/CFNetwork style",
                profile.name
            );
        }
    }

    #[test]
    fn chrome_149_matches_148_wire_fingerprint() {
        // Verified by capturing real Chrome 149.0.7827.54 via profile-collector:
        // its TLS fingerprint is byte-identical to Chrome 148. Lock that in so a
        // future hand-edit can't silently diverge them without a recapture.
        let c149 = chrome_149();
        let c148 = chrome_148();
        assert_eq!(c149.name, "Chrome 149");
        assert_eq!(c149.cipher_suites, c148.cipher_suites);
        assert_eq!(c149.supported_groups, c148.supported_groups);
        assert_eq!(c149.signature_algorithms, c148.signature_algorithms);
        assert_eq!(c149.key_share_curves, c148.key_share_curves);
        assert_eq!(c149.alpn_protocols, c148.alpn_protocols);
        assert_eq!(c149.alps_protocols, c148.alps_protocols);
        assert_eq!(c149.compress_cert_algorithms, c148.compress_cert_algorithms);
        // Same extension SET (per-connection order shuffle aside).
        let mut e149: Vec<u16> = c149.extensions.iter().map(|e| e.extension_type).collect();
        let mut e148: Vec<u16> = c148.extensions.iter().map(|e| e.extension_type).collect();
        e149.sort_unstable();
        e148.sort_unstable();
        assert_eq!(e149, e148);
    }

    #[test]
    fn chrome_150_adds_mldsa_sig_algs_over_149() {
        // Verified by capturing real Chrome 150.0.7871.47 via profile-collector:
        // the ONLY wire change vs Chrome 149 is signature_algorithms — Chrome 150
        // prepends three ML-DSA codepoints 0x0904/0x0905/0x0906 (2308/2309/2310).
        // Everything else is identical to 149. Lock both facts in so a future
        // hand-edit can't silently drop the ML-DSA prefix or diverge the rest.
        let c150 = chrome_150();
        let c149 = chrome_149();
        assert_eq!(c150.name, "Chrome 150");

        // The distinguishing change: 3 ML-DSA sig algs in front of 149's list.
        assert_eq!(
            c150.signature_algorithms,
            [&[2308u16, 2309, 2310][..], &c149.signature_algorithms[..]].concat()
        );
        assert_ne!(c150.signature_algorithms, c149.signature_algorithms);

        // Everything else matches Chrome 149 on the wire.
        assert_eq!(c150.cipher_suites, c149.cipher_suites);
        assert_eq!(c150.supported_groups, c149.supported_groups);
        assert_eq!(c150.key_share_curves, c149.key_share_curves);
        assert_eq!(c150.alpn_protocols, c149.alpn_protocols);
        assert_eq!(c150.alps_protocols, c149.alps_protocols);
        assert_eq!(c150.compress_cert_algorithms, c149.compress_cert_algorithms);
        // Same extension SET (per-connection order shuffle aside).
        let mut e150: Vec<u16> = c150.extensions.iter().map(|e| e.extension_type).collect();
        let mut e149: Vec<u16> = c149.extensions.iter().map(|e| e.extension_type).collect();
        e150.sort_unstable();
        e149.sort_unstable();
        assert_eq!(e150, e149);
    }

    #[test]
    fn chrome_151_matches_chrome_150_tcp_stable_fields() {
        let mut c151 = serde_json::to_value(chrome_151()).unwrap();
        let mut c150 = serde_json::to_value(chrome_150()).unwrap();
        c151.as_object_mut().unwrap().remove("name");
        c150.as_object_mut().unwrap().remove("name");
        assert_eq!(c151, c150);
    }

    #[test]
    fn chrome_152_adds_capture_verified_trust_anchor_ids() {
        let profile = chrome_152();
        let trust_anchors = profile
            .extensions
            .iter()
            .find(|extension| extension.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .expect("Chrome 152 should advertise trust-anchor identifiers");

        match &trust_anchors.source {
            ExtensionSource::TrustAnchorIds { ids, shuffle } => {
                assert_eq!(ids.len(), 32);
                assert!(*shuffle);
            }
            source => panic!("unexpected trust-anchor source: {source:?}"),
        }
    }

    #[test]
    fn chrome_152_is_first_chromium_profile_with_signature_algorithm_grease() {
        assert!(!chrome_149().grease.signature_algorithms);
        assert!(!chrome_150().grease.signature_algorithms);
        assert!(!chrome_151().grease.signature_algorithms);
        assert!(chrome_152().grease.signature_algorithms);
    }

    #[test]
    fn chrome_153_updates_only_capture_verified_trust_anchor_membership() {
        let previous = chrome_152();
        let current = chrome_153();
        let anchors = |profile: &TlsProfile| match &profile
            .extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .unwrap()
            .source
        {
            ExtensionSource::TrustAnchorIds { ids, shuffle } => {
                assert!(*shuffle);
                let mut ids = ids.clone();
                ids.sort();
                ids
            }
            source => panic!("unexpected trust-anchor source: {source:?}"),
        };
        let removed = ["d6790902", "d6790903", "d6790909", "d679090e"];
        let expected: Vec<_> = anchors(&previous)
            .into_iter()
            .filter(|id| !removed.contains(&id.as_str()))
            .collect();
        assert_eq!(anchors(&current), expected);
        assert_eq!(anchors(&current).len(), 28);
        let stable = |mut profile: TlsProfile| {
            profile.name.clear();
            profile
                .extensions
                .retain(|ext| ext.extension_type != ext_type::TRUST_ANCHOR_IDS);
            serde_json::to_value(profile).unwrap()
        };
        assert_eq!(stable(previous), stable(current));
    }

    #[test]
    fn chrome_153_quic_preserves_transport_specific_tls_shape() {
        let profile = chrome_153_quic();
        assert_eq!(profile.name, "Chrome 153 QUIC");
        assert_eq!(profile.session_id_length, 0);
        assert!(!profile.grease.signature_algorithms);
        assert!(!profile.grease.cipher_suite);
        assert!(!profile.grease.extensions);
        assert!(!profile.grease.supported_groups);
        assert!(!profile.grease.supported_versions);
        assert!(!profile.grease.key_share);
        assert!(profile.randomization.as_ref().unwrap().shuffle_extensions);
        assert_eq!(profile.alpn_protocols, ["h3"]);
        assert_eq!(profile.alps_protocols, Some(vec!["h3".into()]));
        assert_eq!(
            profile.signature_algorithms,
            [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
        let anchors = profile
            .extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type::TRUST_ANCHOR_IDS)
            .unwrap();
        assert!(
            matches!(&anchors.source, ExtensionSource::TrustAnchorIds { ids, shuffle: true } if ids.len() == 28)
        );
    }

    #[test]
    fn chrome_154_matches_capture_verified_chrome_153_tls_shape() {
        let mut previous = chrome_153();
        let mut current = chrome_154();
        assert_eq!(current.name, "Chrome 154");
        previous.name.clear();
        current.name.clear();
        assert_eq!(
            serde_json::to_value(current).unwrap(),
            serde_json::to_value(previous).unwrap()
        );

        let quic = chrome_154_quic();
        assert_eq!(quic.name, "Chrome 154 QUIC");
        assert_eq!(
            quic.signature_algorithms,
            chrome_153_quic().signature_algorithms
        );
        assert!(!quic.grease.signature_algorithms);
        assert!(!quic.grease.cipher_suite);
        assert!(!quic.grease.extensions);
        assert!(!quic.grease.supported_groups);
        assert!(!quic.grease.supported_versions);
        assert!(!quic.grease.key_share);
        assert!(quic.randomization.as_ref().unwrap().shuffle_extensions);
    }

    #[test]
    fn firefox_156_matches_public_cloudflare_capture() {
        let profile = firefox_156();
        assert_eq!(profile.name, "Firefox 156");
        assert_eq!(
            profile.cipher_suites,
            [
                4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49171, 49172, 156, 157,
                47, 53,
            ]
        );
        assert_eq!(profile.supported_groups, [4588, 29, 23, 24, 25]);
        assert_eq!(profile.key_share_curves, [4588, 29, 23]);
        assert_eq!(
            profile.signature_algorithms,
            [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513]
        );
        let EchMode::Grease(ech) = profile.ech.expect("Firefox 156 ECH GREASE config") else {
            panic!("Firefox 156 should use ECH GREASE");
        };
        assert_eq!(ech.aead_id, 1);
        assert_eq!(ech.payload_length_min, Some(240));
        assert_eq!(ech.payload_length_max, Some(240));
    }

    #[test]
    fn chrome_148_profile_matches_capture_shape() {
        let profile = chrome_148();

        assert_eq!(profile.name, "Chrome 148");
        assert_eq!(
            profile.tls_client_hello_style,
            TlsClientHelloStyle::ChromiumBoringssl
        );
        assert_eq!(profile.cipher_suites, chrome_144().cipher_suites);
        assert_eq!(profile.supported_groups, vec![4588, 29, 23, 24]);
        assert_eq!(profile.key_share_curves, vec![4588, 29]);
        assert_eq!(
            profile.alpn_protocols,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        assert_eq!(profile.alps_protocols, Some(vec!["h2".to_string()]));
        assert_eq!(profile.compress_cert_algorithms, Some(vec![2]));
        assert!(
            profile
                .randomization
                .as_ref()
                .expect("Chrome 148 should shuffle extensions")
                .shuffle_extensions
        );

        let extension_types = profile
            .extensions
            .iter()
            .map(|extension| extension.extension_type)
            .collect::<Vec<_>>();
        assert_eq!(
            extension_types,
            vec![
                65535, 0, 65037, 16, 43, 11, 51, 35, 17613, 10, 65281, 23, 18, 45, 5, 27, 13,
                65535,
            ]
        );
        assert!(
            !extension_types.contains(&41),
            "pre_shared_key must be generated dynamically, not fixed in the preset"
        );
        assert!(matches!(
            &profile.extensions.first().expect("first extension").source,
            ExtensionSource::Grease
        ));
        assert!(matches!(
            &profile.extensions.last().expect("last extension").source,
            ExtensionSource::Grease
        ));

        match profile
            .ech
            .as_ref()
            .expect("Chrome 148 should use ECH GREASE")
        {
            EchMode::Grease(config) => {
                assert_eq!(config.kdf_id, 1);
                assert_eq!(config.aead_id, 1);
                assert_eq!(config.enc_length, 32);
                assert_eq!(config.payload_length_min, Some(128));
                assert_eq!(config.payload_length_max, Some(224));
            }
            other => panic!("unexpected Chrome 148 ECH mode: {other:?}"),
        }
        assert_eq!(
            profile.ech_outer_extensions.as_deref(),
            Some(&[51, 10, 13, 5, 18, 16, 45, 27, 17613][..])
        );
    }

    #[test]
    fn chrome_150_quic_uses_chrome_150_signature_algorithms() {
        let tcp = chrome_150();
        let quic = chrome_150_quic();

        assert_eq!(quic.name, "Chrome 150 QUIC");
        assert_eq!(quic.tls_min_version, TlsVersion::Tls13);
        assert_eq!(quic.tls_max_version, TlsVersion::Tls13);
        assert_eq!(quic.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(quic.session_id_length, 0);
        assert_eq!(quic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(quic.alps_protocols, Some(vec!["h3".to_string()]));
        assert_eq!(
            &quic.signature_algorithms[..tcp.signature_algorithms.len()],
            tcp.signature_algorithms.as_slice()
        );
        assert_eq!(quic.signature_algorithms.last(), Some(&0x0201));
        assert_eq!(&quic.signature_algorithms[..3], &[0x0904, 0x0905, 0x0906]);
    }

    #[test]
    fn chrome_151_quic_matches_public_h3_capture_signature_algorithms() {
        let quic = chrome_151_quic();

        assert_eq!(quic.name, "Chrome 151 QUIC");
        assert_eq!(
            quic.signature_algorithms,
            vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
    }

    #[test]
    fn chrome_152_quic_matches_public_cloudflare_client_hello() {
        let quic = chrome_152_quic();

        assert_eq!(quic.name, "Chrome 152 QUIC");
        assert!(!quic.grease.signature_algorithms);
        assert_eq!(quic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(
            quic.signature_algorithms,
            vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
        assert!(quic
            .extensions
            .iter()
            .any(|extension| extension.extension_type == ext_type::TRUST_ANCHOR_IDS));
    }

    #[test]
    fn chrome_146_quic_profile_matches_observed_h3_shape() {
        let profile = chrome_146_quic();

        assert_eq!(profile.name, "Chrome 146 QUIC");
        assert_eq!(profile.tls_min_version, TlsVersion::Tls13);
        assert_eq!(profile.tls_max_version, TlsVersion::Tls13);
        assert_eq!(profile.session_id_length, 0);
        assert_eq!(profile.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(profile.alps_protocols, Some(vec!["h3".to_string()]));
        assert!(profile.randomization.is_none());

        // Regression-lock on the captured Chrome 146 QUIC extension order: this
        // value mirrors the constructor, so it guards against accidental edits.
        // Correctness vs. a real Chrome 146 capture is gated independently by the
        // `chrome_146_quic` golden in `lkrequest/tests/fingerprint_regression.rs`.
        let extension_types = profile
            .extensions
            .iter()
            .map(|extension| extension.extension_type)
            .collect::<Vec<_>>();
        assert_eq!(
            extension_types,
            vec![45, 10, 51, 65037, 16, 0, 27, 13, 42, 43, 57, 17613]
        );
    }
}

// TODO: Add more built-in profiles:
// pub fn okhttp3_android14() -> TlsProfile { ... }
// pub fn edge_131() -> TlsProfile { ... }
