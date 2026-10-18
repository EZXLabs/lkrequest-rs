//! A-layer fingerprint regression gate (Tier-0, offline, no browser/network).
//!
//! For each Chrome preset this emits the **actual** wire bytes via `lktls`
//! (ClientHello) / `lkh2` (H2 connection preface), parses them, canonicalizes,
//! and compares against a committed golden. Any diff fails the build — catching
//! changes that alter the on-wire fingerprint, including serializer bugs
//! (the "A2" path: gate the real serialized bytes, not just the preset config).
//!
//! Regenerate goldens after an *intentional* fingerprint change:
//! ```text
//! UPDATE_FINGERPRINTS=1 cargo test -p lkrequest --test fingerprint_regression
//! ```

use std::fs;
use std::path::PathBuf;

use bytes::BytesMut;
use fpverify::{canonicalize_tls, diff_values, CanonicalTlsFingerprint, TlsShapeSpec};
use lkprofile::{h2_fingerprint_from_frames_no_preface, parse_client_hello};
use lktls::handshake::client_hello::ClientHelloBuilder;
use lktls::profile::types::TlsProfile;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fingerprints")
}

/// Compare `current` against the committed golden `<basename>.json`, or
/// (re)write it when `UPDATE_FINGERPRINTS` is set.
fn gate_value(basename: &str, current: serde_json::Value) {
    let dir = golden_dir();
    let path = dir.join(format!("{basename}.json"));

    if std::env::var_os("UPDATE_FINGERPRINTS").is_some() {
        let existing = fs::read_to_string(&path)
            .ok()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok());
        if existing.as_ref() == Some(&current) {
            return;
        }
        fs::create_dir_all(&dir).expect("create golden dir");
        let json = serde_json::to_string_pretty(&current).expect("serialize golden");
        fs::write(&path, format!("{json}\n")).expect("write golden");
        return;
    }

    let golden_str = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden {path:?}; regenerate with UPDATE_FINGERPRINTS=1")
    });
    let golden: serde_json::Value = serde_json::from_str(&golden_str).expect("deserialize golden");

    let diffs = diff_values(&golden, &current);
    assert!(
        diffs.is_empty(),
        "fingerprint regression for `{basename}` \
         (if intended, regenerate with UPDATE_FINGERPRINTS=1):\n{}",
        diffs
            .iter()
            .map(|d| format!("  {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ── TLS ──────────────────────────────────────────────────────────────────────

/// Derive the TLS shape from the preset's randomization config.
fn tls_shape(profile: &TlsProfile) -> TlsShapeSpec {
    let shuffled = profile
        .randomization
        .as_ref()
        .map(|r| r.shuffle_extensions)
        .unwrap_or(false);
    if shuffled {
        // lktls pins only `pre_shared_key` (its `NON_SHUFFLEABLE_EXTENSIONS`).
        TlsShapeSpec::shuffled(vec![0x0029])
    } else {
        TlsShapeSpec::fixed_order()
    }
}

fn check_tls(browser: &str, profile: TlsProfile) {
    let out = ClientHelloBuilder::new(&profile, "example.com")
        .build()
        .expect("ClientHello build should succeed");
    let parsed = parse_client_hello(&out.message).expect("emitted ClientHello should parse");
    let canonical = CanonicalTlsFingerprint::from_parsed(&parsed);
    // Store/compare the shape-canonicalized form so goldens are deterministic
    // (per-connection GREASE + shuffle folded away).
    let comparable = canonicalize_tls(&canonical, &tls_shape(&profile));
    let value = serde_json::to_value(&comparable).expect("serialize canonical TLS");
    gate_value(&format!("{browser}_tls_fresh"), value);
}

fn check_chromium_ech_grease_shape(message: &[u8]) -> [u8; 32] {
    let parsed = parse_client_hello(message).expect("parse ECH GREASE ClientHello");
    let ech = &parsed
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0xfe0d)
        .expect("Chromium ClientHello carries ECH GREASE")
        .data;
    assert_eq!(
        &ech[..5],
        &[0, 0, 1, 0, 1],
        "outer, HKDF-SHA256, AES-128-GCM"
    );
    let enc_length = u16::from_be_bytes([ech[6], ech[7]]) as usize;
    assert_eq!(enc_length, 32);
    assert_eq!(
        ech[8 + enc_length - 1] & 0x80,
        0,
        "canonical X25519 public key"
    );
    let payload_offset = 8 + enc_length;
    let payload_length =
        u16::from_be_bytes([ech[payload_offset], ech[payload_offset + 1]]) as usize;
    assert!([144, 176, 208, 240].contains(&payload_length));
    assert_eq!(ech.len(), payload_offset + 2 + payload_length);
    ech[8..8 + enc_length].try_into().expect("32-byte ECH enc")
}

#[test]
fn chrome_155_tcp_ech_grease_wire_shape() {
    let profile = lktls::profile::presets::chrome_155();
    let mut encs = std::collections::HashSet::new();
    for _ in 0..32 {
        let emitted = ClientHelloBuilder::new(&profile, "www.cloudflare.com")
            .build()
            .expect("emit TCP ClientHello");
        encs.insert(check_chromium_ech_grease_shape(&emitted.message));
    }
    assert_eq!(encs.len(), 32, "fresh TCP ClientHellos use fresh ECH keys");
}

#[test]
fn firefox_156_ech_grease_wire_shape_and_aead_choices() {
    let profile = lktls::profile::presets::firefox_156();
    let mut aeads = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let emitted = ClientHelloBuilder::new(&profile, "www.cloudflare.com")
            .build()
            .expect("emit NSS ClientHello");
        let parsed = parse_client_hello(&emitted.message).expect("parse NSS ClientHello");
        let ech = &parsed
            .extensions
            .iter()
            .find(|ext| ext.extension_type == 0xfe0d)
            .expect("NSS ClientHello carries ECH GREASE")
            .data;
        assert_eq!(&ech[..3], &[0, 0, 1]);
        let aead = u16::from_be_bytes([ech[3], ech[4]]);
        assert!([1, 3].contains(&aead));
        aeads.insert(aead);
        assert_eq!(u16::from_be_bytes([ech[6], ech[7]]), 32);
        assert_eq!(u16::from_be_bytes([ech[40], ech[41]]), 240);
        assert_eq!(ech.len(), 42 + 240);
    }
    assert_eq!(aeads.into_iter().collect::<Vec<_>>(), [1, 3]);
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_155_quic_ech_grease_wire_shape() {
    let config = lktls_quic::LktlsQuicClientConfig::new(lktls::profile::presets::chrome_155_quic())
        .alps_payload(lkh3::encode_alps_h3_settings(&lkh3::chrome_155_h3()));
    let mut encs = std::collections::HashSet::new();
    for _ in 0..32 {
        let emitted = config
            .emit_initial_client_hello("www.cloudflare.com", Vec::new())
            .expect("emit QUIC ClientHello");
        encs.insert(check_chromium_ech_grease_shape(&emitted));
    }
    assert_eq!(encs.len(), 32, "fresh QUIC ClientHellos use fresh ECH keys");
}

#[test]
fn firefox_156_matches_public_capture_hashes() {
    let profile = lktls::profile::presets::firefox_156();
    let out = ClientHelloBuilder::new(&profile, "www.cloudflare.com")
        .build()
        .expect("Firefox 156 ClientHello build should succeed");
    let parsed = parse_client_hello(&out.message).expect("parse Firefox 156 ClientHello");
    let fingerprint = lkprofile::collect_tls_fingerprint(&parsed);
    assert_eq!(fingerprint.ja3_hash, "9d42e90b0225e779f03141ddcd699df2");
    assert_eq!(fingerprint.ja4_prefix, "t13d1517h2");
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_153_quic_tls() {
    let profile = lktls::profile::presets::chrome_153_quic();
    let message = lktls_quic::LktlsQuicClientConfig::new(profile.clone())
        .alps_payload(lkh3::encode_alps_h3_settings(&lkh3::chrome_153_h3()))
        .emit_initial_client_hello("example.com", Vec::new())
        .expect("emit QUIC ClientHello");
    let parsed = parse_client_hello(&message).expect("parse QUIC ClientHello");
    // Chrome 153 QUIC drops the TCP-only TLS GREASE cipher-suite slot.
    assert!(
        !parsed
            .cipher_suites
            .iter()
            .any(|&suite| suite & 0x0f0f == 0x0a0a && suite >> 8 == suite & 0xff),
        "Chrome 153 QUIC ClientHello must not carry a GREASE cipher suite"
    );
    let canonical = CanonicalTlsFingerprint::from_parsed(&parsed);
    gate_value(
        "chrome_153_quic_tls_fresh",
        serde_json::to_value(canonicalize_tls(&canonical, &tls_shape(&profile))).unwrap(),
    );
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_154_quic_tls() {
    let profile = lktls::profile::presets::chrome_154_quic();
    let message = lktls_quic::LktlsQuicClientConfig::new(profile.clone())
        .alps_payload(lkh3::encode_alps_h3_settings(&lkh3::chrome_154_h3()))
        .emit_initial_client_hello("example.com", Vec::new())
        .expect("emit QUIC ClientHello");
    let parsed = parse_client_hello(&message).expect("parse QUIC ClientHello");
    assert!(
        !parsed
            .cipher_suites
            .iter()
            .any(|&suite| suite & 0x0f0f == 0x0a0a && suite >> 8 == suite & 0xff),
        "Chrome 154 QUIC ClientHello must not carry a GREASE cipher suite"
    );
    let canonical = CanonicalTlsFingerprint::from_parsed(&parsed);
    gate_value(
        "chrome_154_quic_tls_fresh",
        serde_json::to_value(canonicalize_tls(&canonical, &tls_shape(&profile))).unwrap(),
    );
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_155_quic_tls() {
    let profile = lktls::profile::presets::chrome_155_quic();
    let message = lktls_quic::LktlsQuicClientConfig::new(profile.clone())
        .alps_payload(lkh3::encode_alps_h3_settings(&lkh3::chrome_155_h3()))
        .emit_initial_client_hello("example.com", Vec::new())
        .expect("emit QUIC ClientHello");
    let parsed = parse_client_hello(&message).expect("parse QUIC ClientHello");
    assert_eq!(
        parsed.cipher_suites,
        [0x1301, 0x1302, 0x1303],
        "Chrome 155 QUIC uses TLS 1.3 suites without TCP GREASE"
    );
    let canonical = CanonicalTlsFingerprint::from_parsed(&parsed);
    gate_value(
        "chrome_155_quic_tls_fresh",
        serde_json::to_value(canonicalize_tls(&canonical, &tls_shape(&profile))).unwrap(),
    );
}

// ── HTTP/2 ─────────────────────────────────────────────────────────────────

/// Emit the H2 preface and first navigation request, then independently parse
/// every gated dimension from the wire, including HPACK pseudo-header order
/// and HEADERS priority. The existing goldens describe this navigation context.
fn h2_fingerprint_value(profile: &lkh2::profile::H2Profile) -> serde_json::Value {
    h2_fingerprint_from_wire(&h2_navigation_wire(profile))
}

fn h2_navigation_wire(profile: &lkh2::profile::H2Profile) -> BytesMut {
    let (mut engine, preface) = lkh2::engine::H2Engine::client(profile);
    let mut buf = BytesMut::new();
    engine.encode_frames(&preface, &mut buf);

    let mut request = http::Request::builder()
        .uri("https://example.com/")
        .body(None)
        .expect("build navigation request");
    request
        .extensions_mut()
        .insert(lkh2::profile::RequestPriority::navigation());
    let stream_id = engine.open_stream();
    let frames = engine.build_request(stream_id, request);
    engine.encode_frames(&frames, &mut buf);
    buf
}

fn h2_fingerprint_from_wire(wire: &[u8]) -> serde_json::Value {
    let parsed =
        h2_fingerprint_from_frames_no_preface(wire).expect("emitted H2 request should parse");

    serde_json::json!({
        "initial_stream_id": parsed.profile.initial_stream_id,
        "settings": parsed.profile.settings,
        "window_update": parsed.profile.window_update,
        "priority_frames": parsed.profile.priority_frames,
        "pseudo_header_order": parsed.profile.pseudo_header_order,
        "headers_priority": parsed.profile.headers_priority,
    })
}

fn check_h2(browser: &str, profile: lkh2::profile::H2Profile) {
    gate_value(&format!("{browser}_h2"), h2_fingerprint_value(&profile));
}

#[test]
fn h2_priority_policy_round_trip_preserves_both_strategies() {
    for (policy, spelling) in [
        (lkh2::profile::StreamDepPolicy::Chain, "chain"),
        (
            lkh2::profile::StreamDepPolicy::PriorityChain,
            "priority_chain",
        ),
    ] {
        let mut profile = lkh2::profile::chrome_155_h2();
        profile.priority_config.stream_dep_policy = policy;
        let json = serde_json::to_value(&profile).unwrap();
        assert_eq!(json["priority_config"]["stream_dep_policy"], spelling);
        let parsed: lkprofile::H2ProfileData = serde_json::from_value(json).unwrap();
        let restored: lkh2::profile::H2Profile =
            serde_json::from_value(serde_json::to_value(parsed).unwrap()).unwrap();
        assert_eq!(restored.priority_config.stream_dep_policy, policy);
    }
}

#[test]
fn firefox_156_navigation_uses_captured_wire_weight() {
    let wire = h2_navigation_wire(&lkh2::profile::firefox_156_h2());
    let parsed = h2_fingerprint_from_frames_no_preface(&wire).expect("parse Firefox H2 wire");
    let priority = parsed
        .profile
        .headers_priority
        .expect("Firefox navigation has priority");
    assert_eq!(
        priority.weight, 41,
        "wire weight 41 represents semantic weight 42"
    );
    assert!(!priority.exclusive);
    assert_eq!(priority.stream_dependency, 0);
}

#[tokio::test]
async fn firefox_156_native_h2_driver_matches_browser_golden() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let profile = lkh2::profile::firefox_156_h2();
    let (client_io, mut peer) = tokio::io::duplex(65536);
    let (sender, driver) =
        lkh2::driver::spawn_driver_with_behavior(client_io, &profile, Some(profile.behavior()))
            .await
            .expect("spawn native H2 driver");
    let request = tokio::spawn(async move {
        let ready = lkh2::H2Sender::Native(sender)
            .ready()
            .await
            .expect("native sender ready");
        let request = lkh2::NativeH2Request::new(
            http::Method::GET,
            "https://example.com/".parse().unwrap(),
            http::HeaderMap::new(),
            None,
            Some(lkh2::profile::RequestPriority::navigation()),
        );
        ready
            .send_native_request(request)
            .await_response()
            .await
            .expect("receive native response")
    });
    let wire = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut magic = [0; 24];
        peer.read_exact(&mut magic)
            .await
            .expect("read native preface magic");
        assert_eq!(&magic, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // The in-memory peer sends empty SETTINGS and acknowledges the client.
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0])
            .await
            .expect("send server SETTINGS");
        let mut wire = Vec::new();
        let response_stream_id = loop {
            let mut header = [0; 9];
            peer.read_exact(&mut header)
                .await
                .expect("read emitted frame header");
            let length =
                ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            assert!(length <= 16384);
            let mut payload = vec![0; length];
            peer.read_exact(&mut payload)
                .await
                .expect("read emitted frame payload");
            wire.extend_from_slice(&header);
            wire.extend_from_slice(&payload);
            if header[3] == 1 {
                assert_ne!(header[4] & 4, 0, "navigation HEADERS are complete");
                break u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
            }
        };
        assert_eq!(response_stream_id, 3);
        // END_STREAM + END_HEADERS, HPACK indexed :status 200.
        let mut response = [0, 0, 1, 1, 5, 0, 0, 0, 0, 0x88];
        response[5..9].copy_from_slice(&response_stream_id.to_be_bytes());
        peer.write_all(&response).await.expect("send response");
        assert_eq!(
            request.await.expect("native request task").status(),
            http::StatusCode::OK
        );
        wire
    })
    .await
    .expect("native driver fingerprint capture completes");
    drop(peer);
    driver.abort();
    let _ = driver.await;
    gate_value("firefox_156_h2", h2_fingerprint_from_wire(&wire));
}

#[test]
fn h2_gate_detects_serialized_headers_mutations() {
    let wire = h2_navigation_wire(&lkh2::profile::chrome_155_h2());
    let golden: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(golden_dir().join("chrome_155_h2.json")).expect("read H2 golden"),
    )
    .expect("parse H2 golden");
    assert!(diff_values(&golden, &h2_fingerprint_from_wire(&wire)).is_empty());

    let mut offset = 0;
    while wire[offset + 3] != 0x01 {
        let length = ((wire[offset] as usize) << 16)
            | ((wire[offset + 1] as usize) << 8)
            | wire[offset + 2] as usize;
        offset += 9 + length;
        assert!(offset + 9 <= wire.len(), "navigation must emit HEADERS");
    }
    assert_ne!(wire[offset + 4] & 0x20, 0, "navigation carries priority");
    let payload = offset + 9;
    assert_eq!(wire[payload + 5], 0x82, "first HPACK field is :method GET");

    // Mutate serialized bytes after the engine has run; the profile stays intact.
    for (index, xor, field) in [
        (payload, 0x80, "headers_priority.exclusive"),
        (payload + 1, 0x01, "headers_priority.stream_dependency"),
        (payload + 4, 0x01, "headers_priority.weight"),
        (payload + 5, 0x05, "pseudo_header_order"),
    ] {
        let mut mutated = wire.clone();
        mutated[index] ^= xor;
        let diffs = diff_values(&golden, &h2_fingerprint_from_wire(&mutated));
        assert!(
            diffs.iter().any(|diff| diff.path.starts_with(field)),
            "wire mutation in {field} must be detected: {diffs:?}"
        );
    }
}

// ── QUIC / HTTP-3 (feature-gated) ──────────────────────────────────────────
//
// Config-level for now: the fingerprint is derived from the `lkh3::QuicProfile`
// via `lkprofile::collect_quic_fingerprint` (mirrors profile_collector's
// `quic_fingerprint_from_profile`). This gates transport-parameter order/values,
// the transport hash, H3 SETTINGS, pseudo-header order, and packetization
// against changes to the preset. A future refinement can emit a real QUIC
// Initial to gate the transport bytes at the wire level (A2). H3 control-stream
// fields are independently parsed from actual local QUIC streams and compared
// directly with these same golden files in quic_local_e2e.rs. The transport and
// pseudo-header observations here remain configuration-level.

#[cfg(feature = "quic-h3")]
fn quic_packetization(
    p: &lkh3::QuicPacketizationProfile,
) -> lkprofile::QuicPacketizationFingerprint {
    lkprofile::QuicPacketizationFingerprint {
        initial_mtu: p.initial_mtu,
        initial_datagram_size: p.initial_datagram_size,
        disable_mtu_discovery: p.disable_mtu_discovery,
        enable_segmentation_offload: p.enable_segmentation_offload,
        enable_ecn: p.enable_ecn,
        initial_frame_layout: if p.initial_packet_chaos {
            Some("chromium_chaos".into())
        } else {
            p.initial_frame_layout.as_ref().map(|layout| {
                layout
                    .packets
                    .iter()
                    .map(|packet| {
                        let frames = packet
                            .frames
                            .iter()
                            .map(|frame| match frame {
                                lkh3::InitialFrameElement::Crypto { offset, length } => {
                                    format!("crypto@{offset}+{length}")
                                }
                                lkh3::InitialFrameElement::Padding { length } => {
                                    format!("padding+{length}")
                                }
                                lkh3::InitialFrameElement::Ping => "ping".to_string(),
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("pn{}[{frames}]", packet.packet_number)
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            })
        },
    }
}

#[cfg(feature = "quic-h3")]
fn quic_fingerprint_value(profile: &lkh3::QuicProfile) -> serde_json::Value {
    let tp = &profile.transport_params;
    let mut transport_parameters = vec![
        ("max_idle_timeout".to_string(), tp.max_idle_timeout),
        ("initial_max_data".to_string(), tp.initial_max_data),
        (
            "initial_max_stream_data_bidi_local".to_string(),
            tp.initial_max_stream_data_bidi_local,
        ),
        (
            "initial_max_stream_data_bidi_remote".to_string(),
            tp.initial_max_stream_data_bidi_remote,
        ),
        (
            "initial_max_stream_data_uni".to_string(),
            tp.initial_max_stream_data_uni,
        ),
        (
            "initial_max_streams_bidi".to_string(),
            tp.initial_max_streams_bidi,
        ),
        (
            "initial_max_streams_uni".to_string(),
            tp.initial_max_streams_uni,
        ),
        (
            "active_connection_id_limit".to_string(),
            tp.active_connection_id_limit,
        ),
    ];
    if let Some(v) = tp.max_udp_payload_size {
        transport_parameters.push(("max_udp_payload_size".into(), v));
    }
    if let Some(v) = tp.max_datagram_frame_size {
        transport_parameters.push(("max_datagram_frame_size".into(), v));
    }

    let pseudo_header_order = profile
        .h3
        .pseudo_header_order
        .iter()
        .map(|id| match id {
            lkh3::PseudoHeaderId::Method => ":method",
            lkh3::PseudoHeaderId::Authority => ":authority",
            lkh3::PseudoHeaderId::Scheme => ":scheme",
            lkh3::PseudoHeaderId::Path => ":path",
            lkh3::PseudoHeaderId::Protocol => ":protocol",
        })
        .map(str::to_string)
        .collect::<Vec<_>>();

    let input = lkprofile::QuicFingerprintInput {
        transport_parameters,
        h3: lkprofile::H3FingerprintInput {
            settings: profile.h3.effective_settings(),
            pseudo_header_order,
            pseudo_header_order_token: profile.h3.pseudo_header_order_token(),
            grease_settings: profile.h3.grease_settings,
        },
        connection_id_length: profile.connection_id_length,
        initial_destination_connection_id_length: profile.initial_destination_connection_id_length,
        grease_transport_params: tp.grease_transport_params,
        send_min_ack_delay: tp.send_min_ack_delay,
        send_reserved_transport_parameter: tp.send_reserved_transport_parameter,
        extra_transport_parameters: tp.extra_transport_parameters.clone(),
        transport_parameter_order: tp.transport_parameter_order.clone(),
        packetization: quic_packetization(&profile.packetization),
    };
    let fp = lkprofile::collect_quic_fingerprint(&input);
    let mut value = serde_json::to_value(&fp).expect("serialize QUIC fingerprint");

    // Gate the H3 control-stream frame shape too: the default RFC 9218
    // PRIORITY_UPDATE frames and whether a reserved control-stream GREASE frame
    // is emitted. `collect_quic_fingerprint` does not carry these, so fold them
    // in from the profile — a regression that empties `priority_updates` or
    // flips `send_control_grease_frame` then fails offline (the wire-level test
    // in `quic_local_e2e.rs` is the on-wire counterpart).
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "priority_updates".into(),
            serde_json::json!(profile.h3.priority_updates),
        );
        obj.insert(
            "send_control_grease_frame".into(),
            serde_json::json!(profile.h3.send_control_grease_frame),
        );
        if tp.randomize_grease_shape {
            obj.insert("randomize_grease_shape".into(), serde_json::json!(true));
        }
        if profile.h3.chromium_grease {
            obj.insert("chromium_grease".into(), serde_json::json!(true));
        }
        if profile.h3.request_priority_updates {
            obj.insert("request_priority_updates".into(), serde_json::json!(true));
        }
        if profile.packetization.initial_packet_chaos {
            obj.insert("initial_packet_chaos".into(), serde_json::json!(true));
        }
    }
    value
}

#[cfg(feature = "quic-h3")]
fn check_quic(basename: &str, profile: lkh3::QuicProfile) {
    gate_value(basename, quic_fingerprint_value(&profile));
}

// ── QUIC/H3 0-RTT (resumed) ClientHello fingerprint ──────────────────────────
//
// Emits the resumed/0-RTT TLS ClientHello (with a session ticket seeded) and
// checks the resumption-specific structure: `early_data` (0x002a) present and
// `pre_shared_key` (0x0029) pinned LAST (RFC 8446 §4.2.11), with the rest of the
// fingerprint identical to the fresh ClientHello. Also locks it as a golden.
// (The PSK extension payload carries a wall-clock-dependent obfuscated ticket
// age + binder, so the canonical only fingerprints its presence/position.)

#[cfg(feature = "quic-h3")]
fn synthetic_h3_ticket() -> lktls::session_store::SessionTicketData {
    lktls::session_store::SessionTicketData {
        ticket: vec![1, 2, 3, 4],
        resumption_psk: vec![0xAB; 32],
        tls_version: lktls::session_store::TicketTlsVersion::Tls13,
        used_extended_master_secret: None,
        cipher_suite: 0x1301,
        lifetime_secs: 3600,
        age_add: 0,
        received_at: std::time::Instant::now(),
        alpn: None, // None bypasses the ALPN-compatibility check in the resumption path
        alps: Default::default(),
        hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
        aead_algorithm: lktls::crypto::aead::AeadAlgorithm::Aes128Gcm,
        master_secret: Vec::new(),
        max_early_data_size: 0xffff_ffff, // RFC 9001 §4.6.1: QUIC allows only this value
        peer_transport_parameters: Some(vec![0x01, 0x00]),
    }
}

#[cfg(feature = "quic-h3")]
fn emit_quic_client_hello(
    store: std::sync::Arc<dyn lktls::session_store::SessionStore>,
) -> CanonicalTlsFingerprint {
    let mut profile = lktls::profile::presets::chrome_146_quic();
    profile.session_resumption.tls13_psk = true;
    let config = lktls_quic::LktlsQuicClientConfig::new(profile)
        .session_store(store)
        .port(443);
    let bytes = config
        .emit_initial_client_hello("localhost", Vec::new())
        .expect("emit QUIC ClientHello");
    let parsed = parse_client_hello(&bytes).expect("parse QUIC ClientHello");
    CanonicalTlsFingerprint::from_parsed(&parsed)
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_146_quic_tls_resumed() {
    use lktls::session_store::{InMemorySessionStore, SessionStore};
    use std::sync::Arc;

    let fresh = emit_quic_client_hello(Arc::new(InMemorySessionStore::new()));

    let store = Arc::new(InMemorySessionStore::new());
    store.store("localhost:443", synthetic_h3_ticket());
    let resumed = emit_quic_client_hello(store);

    let types = |fp: &CanonicalTlsFingerprint| -> Vec<u16> {
        fp.extensions.iter().map(|e| e.extension_type).collect()
    };
    let fresh_types = types(&fresh);
    let resumed_types = types(&resumed);

    // Fresh must NOT carry the resumption extensions.
    assert!(
        !fresh_types.contains(&0x0029) && !fresh_types.contains(&0x002a),
        "fresh ClientHello must not carry PSK/early_data; got {fresh_types:#06x?}"
    );
    // Resumed must carry early_data (0x002a) ...
    assert!(
        resumed_types.contains(&0x002a),
        "resumed ClientHello must carry early_data (0x002a); got {resumed_types:#06x?}"
    );
    // ... and pre_shared_key (0x0029) MUST be the last extension (RFC 8446 §4.2.11).
    assert_eq!(
        resumed_types.last(),
        Some(&0x0029),
        "pre_shared_key (0x0029) must be the last extension; got {resumed_types:#06x?}"
    );
    // Resumption is purely additive: the base extension set equals the fresh set
    // (compared as a set — the profile shuffles extension order per connection).
    let mut base: Vec<u16> = resumed_types
        .iter()
        .copied()
        .filter(|t| *t != 0x0029 && *t != 0x002a)
        .collect();
    let mut fresh_set = fresh_types.clone();
    base.sort_unstable();
    fresh_set.sort_unstable();
    assert_eq!(
        base, fresh_set,
        "resumed base extensions must equal the fresh set (resumption is additive)"
    );

    // Lock the resumed-mode fingerprint as a golden.
    let shape = tls_shape(&lktls::profile::presets::chrome_146_quic());
    let comparable = canonicalize_tls(&resumed, &shape);
    gate_value(
        "chrome_146_quic_tls_resumed",
        serde_json::to_value(&comparable).expect("serialize resumed canonical"),
    );
}

// ── Test registry ────────────────────────────────────────────────────────────

// Chrome 153 and 154 TLS (TCP and QUIC) and H2 goldens come from Wireshark
// captures against public Cloudflare. QUIC profile goldens additionally gate
// modeled runtime configuration, not packet layout.

macro_rules! tls_gate {
    ($($name:ident => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_tls(stringify!($name), $preset);
            }
        )+
    };
}

macro_rules! h2_gate {
    ($($name:ident => $browser:literal => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_h2($browser, $preset);
            }
        )+
    };
}

#[cfg(feature = "quic-h3")]
macro_rules! quic_gate {
    ($($name:ident => $basename:literal => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_quic($basename, $preset);
            }
        )+
    };
}

tls_gate! {
    chrome_131 => lktls::profile::presets::chrome_131(),
    chrome_144 => lktls::profile::presets::chrome_144(),
    chrome_145 => lktls::profile::presets::chrome_145(),
    chrome_146 => lktls::profile::presets::chrome_146(),
    chrome_147 => lktls::profile::presets::chrome_147(),
    chrome_148 => lktls::profile::presets::chrome_148(),
    chrome_149 => lktls::profile::presets::chrome_149(),
    chrome_150 => lktls::profile::presets::chrome_150(),
    chrome_151 => lktls::profile::presets::chrome_151(),
    chrome_152 => lktls::profile::presets::chrome_152(),
    chrome_153 => lktls::profile::presets::chrome_153(),
    chrome_154 => lktls::profile::presets::chrome_154(),
    chrome_155 => lktls::profile::presets::chrome_155(),
    firefox_133 => lktls::profile::presets::firefox_133(),
    firefox_147 => lktls::profile::presets::firefox_147(),
    firefox_156 => lktls::profile::presets::firefox_156(),
    safari_18 => lktls::profile::presets::safari_18(),
    safari_26 => lktls::profile::presets::safari_26(),
}

h2_gate! {
    chrome_131_h2 => "chrome_131" => lkh2::profile::chrome_131_h2(),
    chrome_144_h2 => "chrome_144" => lkh2::profile::chrome_144_h2(),
    chrome_145_h2 => "chrome_145" => lkh2::profile::chrome_145_h2(),
    chrome_146_h2 => "chrome_146" => lkh2::profile::chrome_146_h2(),
    chrome_147_h2 => "chrome_147" => lkh2::profile::chrome_147_h2(),
    chrome_148_h2 => "chrome_148" => lkh2::profile::chrome_148_h2(),
    chrome_149_h2 => "chrome_149" => lkh2::profile::chrome_149_h2(),
    chrome_150_h2 => "chrome_150" => lkh2::profile::chrome_150_h2(),
    chrome_151_h2 => "chrome_151" => lkh2::profile::chrome_151_h2(),
    chrome_152_h2 => "chrome_152" => lkh2::profile::chrome_152_h2(),
    chrome_153_h2 => "chrome_153" => lkh2::profile::chrome_153_h2(),
    chrome_154_h2 => "chrome_154" => lkh2::profile::chrome_154_h2(),
    chrome_155_h2 => "chrome_155" => lkh2::profile::chrome_155_h2(),
    firefox_133_h2 => "firefox_133" => lkh2::profile::firefox_133_h2(),
    firefox_147_h2 => "firefox_147" => lkh2::profile::firefox_147_h2(),
    firefox_156_h2 => "firefox_156" => lkh2::profile::firefox_156_h2(),
    safari_18_h2 => "safari_18" => lkh2::profile::safari_18_h2(),
    safari_26_h2 => "safari_26" => lkh2::profile::safari_26_h2(),
}

#[cfg(feature = "quic-h3")]
quic_gate! {
    chrome_146_quic => "chrome_146_quic" => lkh3::chrome_146_quic(),
    chrome_150_quic => "chrome_150_quic" => lkh3::chrome_150_quic(),
    chrome_151_quic => "chrome_151_quic" => lkh3::chrome_151_quic(),
    chrome_152_quic => "chrome_152_quic" => lkh3::chrome_152_quic(),
    chrome_153_quic => "chrome_153_quic" => lkh3::chrome_153_quic(),
    chrome_154_quic => "chrome_154_quic" => lkh3::chrome_154_quic(),
    chrome_155_quic => "chrome_155_quic" => lkh3::chrome_155_quic(),
    chrome_generic_quic => "chrome_generic_quic" => lkh3::chrome_quic(),
}
