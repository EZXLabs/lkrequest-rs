use lkrequest::preset::{
    self, ClientPreset, PresetDocument, PresetErrorCode, PresetLimits, PresetLoader,
};
use lkrequest::Client;
use serde_json::{json, Value};

fn bundle() -> Value {
    serde_json::from_str(
        &PresetDocument::from_preset("test", &preset::chrome_157())
            .unwrap()
            .to_json_string()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn applying_complete_preset_clears_previous_optional_dimensions() {
    let mut empty = preset::firefox_156();
    empty.header_order.clear();
    empty.h3_header_order = None;
    empty.cookie_order = None;
    empty.quic_tls_profile = None;
    let client = Client::builder()
        .preset(preset::chrome_157())
        .h3_header_order(vec!["accept"])
        .cookie_order(vec!["old"])
        .preset(empty)
        .build();
    assert!(
        client.quic_tls_profile().is_none(),
        "stale QUIC TLS survived preset replacement"
    );
    assert!(client.header_order().is_none());
    assert!(client.h3_header_order().is_none());
    assert!(client.cookie_order().is_none());
}

#[test]
fn every_builtin_roundtrips_including_runtime_behavior() {
    for preset in [
        preset::chrome_131(),
        preset::chrome_144(),
        preset::chrome_145(),
        preset::chrome_146(),
        preset::chrome_147(),
        preset::chrome_148(),
        preset::chrome_149(),
        preset::chrome_150(),
        preset::chrome_151(),
        preset::chrome_152(),
        preset::chrome_153(),
        preset::chrome_154(),
        preset::chrome_155(),
        preset::chrome_156(),
        preset::chrome_157(),
        preset::firefox_133(),
        preset::firefox_147(),
        preset::firefox_156(),
        preset::safari_18(),
        preset::safari_26(),
    ] {
        let name = preset.tls_profile.name.clone();
        let document =
            PresetDocument::from_preset(&name, &preset).unwrap_or_else(|e| panic!("{name}: {e}"));
        let text = document.to_json_string().unwrap();
        let reloaded = PresetDocument::from_json_str(&text).unwrap();
        assert_eq!(
            document.to_json_string().unwrap(),
            reloaded.to_json_string().unwrap()
        );
        assert_eq!(
            reloaded.preset().default_protocol_policy,
            preset.default_protocol_policy
        );
        let a = preset.h2_profile.behavior();
        let b = reloaded.preset().h2_profile.behavior();
        for (name, value) in [(":method", "GET"), ("accept", "*/*"), ("cookie", "a=1;b=2")] {
            assert_eq!(
                a.hpack_policy.encoding_for(name, value),
                b.hpack_policy.encoding_for(name, value)
            );
        }
        let mut a_flow = a.flow_control.box_clone();
        let mut b_flow = b.flow_control.box_clone();
        for n in [10, 100, 400, 800] {
            assert_eq!(
                a_flow.on_data_received(1, n, 1000, 1000),
                b_flow.on_data_received(1, n, 1000, 1000)
            );
        }
        Client::builder()
            .preset(reloaded.into_preset())
            .try_build()
            .unwrap();
    }
}

fn reject(value: Value, expected: PresetErrorCode) {
    let error = PresetDocument::from_json_str(&value.to_string()).unwrap_err();
    assert_eq!(error.code, expected, "{error}");
    assert!(error.path.starts_with('/'));
}

#[test]
fn rejects_unknown_fields_and_conflicting_profiles() {
    let mut v = bundle();
    v["tls_profile"]["grease"]["typo"] = json!(false);
    let error = PresetDocument::from_json_str(&v.to_string()).unwrap_err();
    assert_eq!(error.code, PresetErrorCode::UnknownField);
    assert_eq!(error.path, "/tls_profile/grease/typo");
    let mut v = bundle();
    v["tls_profile"]["randomization"] =
        serde_json::to_value(lkrequest::lktls::profile::types::RandomizationConfig::default())
            .unwrap();
    v["tls_profile"]["randomization"]["a/b.c~d"] = json!(1);
    let error = PresetDocument::from_json_str(&v.to_string()).unwrap_err();
    assert_eq!(error.code, PresetErrorCode::UnknownField);
    assert_eq!(error.path, "/tls_profile/randomization/a~1b.c~0d");
    let mut v = bundle();
    v["tls_profile"]["extensions"][0]["source"]["typo"] = json!(1);
    reject(v, PresetErrorCode::UnknownField);
    let mut v = bundle();
    v["runtime"]["h2_behavior"]["flow_control"]["typo"] = json!(1);
    reject(v, PresetErrorCode::UnknownField);
    let mut v = bundle();
    v["h2_profile"]["behavior"] = json!({});
    reject(v, PresetErrorCode::UnknownField);
    let mut v = bundle();
    v["tls_profile"]["cipher_suites"] = json!([]);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["tls_profile"]["session_id_length"] = json!(33);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["h2_profile"]
        .as_object_mut()
        .unwrap()
        .remove("initial_stream_id");
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["tls_profile"]["session_id_length"] = json!("32");
    let error = PresetDocument::from_json_str(&v.to_string()).unwrap_err();
    assert_eq!(error.path, "/tls_profile/session_id_length");
    let mut v = bundle();
    v["tls_profile"]["ech"]["enc_length"] = json!(1000);
    v["tls_profile"]["ech"]["payload_length_min"] = json!(65000);
    v["tls_profile"]["ech"]["payload_length_max"] = Value::Null;
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["tls_profile"]["ech"] = json!({"type": "real", "ech_config_list": "AAA="});
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["header_order"] = json!(["Accept", "accept"]);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["cookie_order"] = json!(["a=b"]);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["runtime"]["h2_behavior"]["write"]["max_data_frame_payload"] = json!(0);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["schema_version"] = json!(3);
    reject(v, PresetErrorCode::UnsupportedVersion);
    let mut v = bundle();
    v["runtime"]["version"] = json!(2);
    reject(v, PresetErrorCode::UnsupportedVersion);
    let mut v = bundle();
    v.as_object_mut().unwrap().remove("quic_tls_profile");
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["quic_profile"] = Value::Null;
    v["runtime"]["protocol"] = json!({"intent":"h3_only", "acquisition":{"type":"establish_best_available"}, "upgrade":"off", "fallback":"no_fallback"});
    reject(v, PresetErrorCode::InvalidProfile);
    reject(
        json!({"tls_profile": {}, "policy_snapshot": {}}),
        PresetErrorCode::LegacyBundleIncomplete,
    );
}

#[test]
fn bounded_strict_json_and_file_loading() {
    for input in [r#"{"name":1,"\u006eame":2}"#, r#"{"a":{"x":1,"x":2}}"#] {
        assert_eq!(
            PresetDocument::from_json_str(input).unwrap_err().code,
            PresetErrorCode::DuplicateKey
        );
    }
    assert_eq!(
        PresetDocument::from_json_slice(&[0xff]).unwrap_err().code,
        PresetErrorCode::InvalidJson
    );
    let text = bundle().to_string();
    assert!(PresetDocument::from_json_str(&(text.clone() + " null")).is_err());
    for limits in [
        PresetLimits {
            max_bytes: 10,
            ..Default::default()
        },
        PresetLimits {
            max_depth: 2,
            ..Default::default()
        },
        PresetLimits {
            max_nodes: 10,
            ..Default::default()
        },
        PresetLimits {
            max_container_entries: 2,
            ..Default::default()
        },
        PresetLimits {
            max_string_bytes: 4,
            ..Default::default()
        },
    ] {
        assert_eq!(
            PresetLoader { limits }
                .from_json_str(&text)
                .unwrap_err()
                .code,
            PresetErrorCode::ResourceLimit
        );
    }
    let path = std::env::temp_dir().join(format!("lkrequest-preset-{}.json", std::process::id()));
    std::fs::write(&path, &text).unwrap();
    assert_eq!(
        ClientPreset::from_json_file(&path)
            .unwrap()
            .tls_profile
            .name,
        "Chrome 157"
    );
    assert_eq!(
        PresetLoader {
            limits: PresetLimits {
                max_bytes: 10,
                ..Default::default()
            }
        }
        .from_json_file(&path)
        .unwrap_err()
        .code,
        PresetErrorCode::ResourceLimit
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn explicit_legacy_migration_preserves_data_and_reconstructs_webview_policies() {
    use lkh2::frame::{DataFrame, H2Frame};
    use lkh2::policy::{FlowControlConfig, HpackFieldEncoding, HpackPolicyConfig};
    use lkrequest::preset::PresetRuntime;
    let mut legacy = bundle();
    let mut runtime: PresetRuntime = serde_json::from_value(legacy["runtime"].take()).unwrap();
    runtime.protocol = lkrequest::preset::ProtocolConfig::from_policy(
        &lkrequest::ProtocolPolicy::crawler_throughput().with_intent(lkrequest::HttpIntent::H2Only),
    )
    .unwrap();
    runtime.h2_behavior.write.separate_end_stream_data = true;
    runtime.h2_behavior.write.max_data_frame_payload = None;
    runtime.h2_behavior.hpack = HpackPolicyConfig::AdaptiveHuffman;
    runtime.h2_behavior.flow_control = FlowControlConfig::Threshold { ratio: 0.5 };
    for key in ["schema_version", "format", "runtime"] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    legacy["quic_profile"] = Value::Null;
    legacy["policy_snapshot"] =
        json!({"default_protocol_policy": "untrusted Debug text, never executed"});
    let document = PresetLoader::default()
        .migrate_legacy_json(legacy.to_string().as_bytes(), runtime)
        .unwrap();
    assert!(
        document.metadata().unwrap()["migration"]["runtime_supplied_by_caller"]
            .as_bool()
            .unwrap()
    );
    let behavior = document.preset().h2_profile.behavior();
    assert_eq!(
        behavior.hpack_policy.encoding_for("x", "~~~"),
        HpackFieldEncoding::IncrementalIndexing {
            huffman_value: false
        }
    );
    assert_eq!(
        behavior.hpack_policy.encoding_for("x", "aaaaaaaaaaa"),
        HpackFieldEncoding::IncrementalIndexing {
            huffman_value: true
        }
    );
    let groups = behavior
        .write_policy
        .group_frames(vec![H2Frame::Data(DataFrame {
            stream_id: 1,
            data: bytes::Bytes::from_static(b"body"),
            end_stream: true,
            padding: None,
        })]);
    assert_eq!(groups.len(), 2);
    assert!(matches!(&groups[0][0], H2Frame::Data(d) if !d.end_stream && d.data == b"body"[..]));
    assert!(matches!(&groups[1][0], H2Frame::Data(d) if d.end_stream && d.data.is_empty()));
    let mut flow = behavior.flow_control.box_clone();
    assert_eq!(flow.on_data_received(1, 499, 1000, 1000), None);
    assert_eq!(flow.on_data_received(1, 1, 1000, 1000), Some(500));
    PresetDocument::from_json_str(&document.to_json_string().unwrap()).unwrap();
}

#[test]
fn final_builder_validation_catches_component_overrides() {
    let preset = PresetDocument::from_json_str(&bundle().to_string())
        .unwrap()
        .into_preset();
    let mut tls = preset.tls_profile.clone();
    tls.cipher_suites.clear();
    assert!(Client::builder()
        .preset(preset.clone())
        .fingerprint(tls)
        .try_build()
        .is_err());
    let mut h2 = preset.h2_profile.clone();
    h2.window_update = u32::MAX;
    assert!(Client::builder()
        .preset(preset)
        .h2_profile(h2)
        .try_build()
        .is_err());
}

#[test]
fn custom_runtime_code_cannot_be_silently_exported() {
    use lkh2::policy::{FrameGroup, FrameWritePolicy, H2Behavior};
    #[derive(Debug, Clone)]
    struct Custom;
    impl FrameWritePolicy for Custom {
        fn group_frames(&self, frames: Vec<lkh2::frame::H2Frame>) -> Vec<FrameGroup> {
            vec![frames]
        }
        fn box_clone(&self) -> Box<dyn FrameWritePolicy> {
            Box::new(self.clone())
        }
    }
    let mut preset = preset::chrome_157();
    preset.h2_profile.behavior = Some(H2Behavior {
        write_policy: Box::new(Custom),
        ..H2Behavior::chrome()
    });
    assert_eq!(
        PresetDocument::from_preset("custom", &preset)
            .unwrap_err()
            .code,
        PresetErrorCode::UnsupportedBehavior
    );
}

#[cfg(not(feature = "quic-h3"))]
#[test]
fn quic_input_requires_the_build_feature() {
    let mut v = bundle();
    v["quic_profile"] = json!({});
    assert_eq!(
        PresetDocument::from_json_str(&v.to_string())
            .unwrap_err()
            .code,
        PresetErrorCode::FeatureUnavailable
    );
}

#[cfg(feature = "quic-h3")]
#[test]
fn quic_varints_are_lossless_decimal_strings() {
    let mut preset = preset::chrome_157();
    preset
        .quic_profile
        .as_mut()
        .unwrap()
        .transport_params
        .max_idle_timeout = (1_u64 << 53) + 1;
    let doc = PresetDocument::from_preset("large", &preset).unwrap();
    let mut v: Value = serde_json::from_str(&doc.to_json_string().unwrap()).unwrap();
    assert_eq!(
        v["quic_profile"]["transport_params"]["max_idle_timeout"],
        "9007199254740993"
    );
    v["quic_profile"]["transport_params"]["max_idle_timeout"] = json!(9007199254740993_u64);
    reject(v, PresetErrorCode::InvalidProfile);
    let mut v = bundle();
    v["quic_profile"]["packetization"]
        .as_object_mut()
        .unwrap()
        .remove("disable_mtu_discovery");
    reject(v, PresetErrorCode::InvalidProfile);
}
