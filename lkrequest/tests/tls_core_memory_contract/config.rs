//! Compilation and first-flight costs through public APIs. Preset/capture
//! parsing, profile construction/deep clones and wire verification are excluded.
//! Arc clones occur inside the scopes; any clone performed by the compiler itself
//! is included. Start includes dynamic inputs, keys, snapshots and record framing,
//! so it must not be described as an isolated encoder or complete handshake.

use std::sync::Arc;

use lktls::config::{
    ClientConfigTemplate, CompileOptions, CompiledClientConfig, ConnectionInputs, Transport,
};
use lktls::connection::ClientConnection;
use lktls::handshake::client_hello_wire::ClientHelloWire;
use lktls::profile::{
    presets,
    types::{ext_type, EchMode, ExtensionSource, TlsProfile},
};

use super::accounting::Owner;

struct Case {
    name: &'static str,
    profile: Arc<TlsProfile>,
    hostname: &'static str,
}

fn cases() -> Vec<Case> {
    let mut ordered = presets::chrome_155();
    ordered.randomization = None;
    ordered.ech = Some(EchMode::Disabled);
    let mut shuffled = presets::chrome_155();
    shuffled.ech = Some(EchMode::Disabled);
    assert!(shuffled.randomization.as_ref().unwrap().shuffle_extensions);
    let mut opaque = ordered.clone();
    opaque.alps_protocols = None;
    opaque
        .extensions
        .iter_mut()
        .find(|extension| extension.extension_type == ext_type::ALPN)
        .unwrap()
        .source = ExtensionSource::RawBytes {
        data: "00020180".into(),
    };

    vec![
        Case {
            name: "editable_ordered",
            profile: Arc::new(ordered),
            hostname: "localhost",
        },
        Case {
            name: "editable_shuffled",
            profile: Arc::new(shuffled),
            hostname: "localhost",
        },
        Case {
            name: "opaque_raw_alpn",
            profile: Arc::new(opaque),
            hostname: "localhost",
        },
    ]
}

fn inputs(case: &Case) -> ConnectionInputs {
    let mut inputs = ConnectionInputs::new(case.hostname, 443);
    inputs.alps_payload = Some(Vec::new());
    inputs
}

fn measure(case: Case) {
    const REUSES: usize = 32;
    const STARTS: usize = 8;
    let plan_owner = Owner::new();
    let config = plan_owner.enter(|| {
        CompiledClientConfig::compile(
            case.profile.clone(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap()
    });
    let compiled = plan_owner.snapshot();
    assert!(compiled.live > 0);
    let template_owner = Owner::new();
    let template = template_owner.enter(|| ClientConfigTemplate::from_compiled(config.clone()));
    let template_bytes = template_owner.snapshot().live;
    let cache_owner = Owner::new();
    for _ in 0..REUSES {
        let cached = cache_owner.enter(|| template.compile().unwrap());
        assert!(Arc::ptr_eq(&config, &cached));
    }
    let cache = cache_owner.snapshot();
    assert_eq!(cache.allocations, 0);
    assert_eq!(cache.reallocations, 0);
    assert_eq!(cache.live, 0);

    // Prime process-global crypto setup outside client accounting. The shared
    // config remains attributed to plan_owner throughout all eight real starts.
    drop(ClientConnection::from_compiled(config.clone(), inputs(&case)).unwrap());
    let mut starts = Vec::with_capacity(STARTS);
    for _ in 0..STARTS {
        let client_owner = Owner::new();
        let client = client_owner
            .enter(|| ClientConnection::from_compiled(config.clone(), inputs(&case)).unwrap());
        let start = client_owner.snapshot();
        let wire = ClientHelloWire::parse(client.output()).unwrap();
        assert_eq!(wire.handshake[0], 1);
        if case.name == "opaque_raw_alpn" {
            let alpn = wire
                .extensions
                .iter()
                .find(|e| e.extension_type == ext_type::ALPN)
                .unwrap();
            assert_eq!(&wire.handshake[alpn.payload.clone()], &[0, 2, 1, 0x80]);
        }
        let output_bytes = client.output().len();
        drop(client);
        assert_eq!(client_owner.snapshot().live, 0);
        assert_eq!(client_owner.snapshot().blocks, 0);
        assert_eq!(plan_owner.snapshot().live, compiled.live);
        assert_eq!(plan_owner.snapshot().allocations, compiled.allocations);
        assert_eq!(plan_owner.snapshot().reallocations, compiled.reallocations);
        starts.push(serde_json::json!({
            "rust_allocations": start.allocations,
            "rust_reallocations": start.reallocations,
            "requested_bytes": start.requested,
            "peak_bytes": start.peak,
            "pending_first_flight_retained_bytes": start.live,
            "first_flight_output_bytes": output_bytes,
            "after_drop_bytes": 0,
        }));
    }
    drop(template);
    assert_eq!(template_owner.snapshot().live, 0);
    assert_eq!(template_owner.snapshot().blocks, 0);
    assert_eq!(plan_owner.snapshot().live, compiled.live);
    drop(config);
    assert_eq!(plan_owner.snapshot().live, 0);
    assert_eq!(plan_owner.snapshot().blocks, 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "compiled_config_and_first_flight",
            "case": case.name,
            "unit": "requested_rust_heap_bytes",
            "transport": "TCP",
            "cold_compile": {
                "rust_allocations": compiled.allocations,
                "rust_reallocations": compiled.reallocations,
                "requested_bytes": compiled.requested,
                "peak_bytes": compiled.peak,
                "plan_retained_bytes": compiled.live,
            "retained_scope": "compiler_created_heap_excluding_shared_input_profile",
                "after_drop_bytes": 0,
            },
            "template_wrapper_retained_bytes": template_bytes,
            "cache_lookups": REUSES,
            "cache_lookup_allocations": cache.allocations,
            "cache_lookup_reallocations": cache.reallocations,
            "client_start_samples": starts,
            "source_profile_parse_and_deep_clone_included": false,
            "compile_internal_profile_clones_included": true,
            "arc_clone_included": true,
            "client_start_scope": "dynamic_inputs_key_generation_snapshot_and_record_framing",
            "input_profile_retained_bytes": null,
            "c_backend_bytes": null,
            "copy_bytes": null,
            "elapsed_ns": null,
        })
    );
}

#[test]
#[ignore = "Deterministic config/start memory matrix; run explicitly with --ignored --nocapture"]
fn compiled_config_cold_cached_and_reused_first_flight_memory() {
    let cases = cases();
    assert_eq!(cases.len(), 3);
    for case in cases {
        measure(case);
    }
}
