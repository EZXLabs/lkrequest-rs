//! Test-only executed encoding copy sites, not total memory traffic. No clocks.
//! Extension codecs, framing, transcripts outside the builder, HPKE internals,
//! allocator relocation, metadata clones and stack/header writes are excluded.

use std::cell::Cell;
use std::sync::Arc;

use super::client_hello::{ClientHelloBuilder, ClientHelloOutput};
use super::client_hello_wire::ClientHelloWire;
use crate::config::{ClientConfigTemplate, CompileOptions, CompiledClientConfig, Transport};
use crate::profile::{
    presets,
    types::{EchMode, ExtensionSource, PaddingStrategy, TlsProfile},
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum CopySite {
    FixedExtension,
    RawExtension,
    PaddingRebuild,
    HelloExtensions,
    InnerPskIdentity,
    InnerPskExtension,
    InnerPskBinder,
    EchInnerExtensions,
    EchReferenceSplice,
    EchCiphertext,
    EchOuterExtensionRebuild,
    EchOuterAssembly,
    EchTranscriptBody,
    EchTranscriptMessage,
}

const SITES: [CopySite; 14] = [
    CopySite::FixedExtension,
    CopySite::RawExtension,
    CopySite::PaddingRebuild,
    CopySite::HelloExtensions,
    CopySite::InnerPskIdentity,
    CopySite::InnerPskExtension,
    CopySite::InnerPskBinder,
    CopySite::EchInnerExtensions,
    CopySite::EchReferenceSplice,
    CopySite::EchCiphertext,
    CopySite::EchOuterExtensionRebuild,
    CopySite::EchOuterAssembly,
    CopySite::EchTranscriptBody,
    CopySite::EchTranscriptMessage,
];

#[derive(Clone, Copy, Default)]
struct Counts {
    bytes: [usize; SITES.len()],
    calls: [usize; SITES.len()],
    hex_decodes: usize,
    hex_input_bytes: usize,
    index_orders: usize,
    selected_index_bytes: usize,
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = Cell::new(Counts::default());
}

fn update(change: impl FnOnce(&mut Counts)) {
    if ACTIVE.with(Cell::get) {
        COUNTS.with(|slot| {
            let mut counts = slot.get();
            change(&mut counts);
            slot.set(counts);
        });
    }
}

pub(crate) fn copied(site: CopySite, bytes: usize) {
    update(|counts| {
        counts.bytes[site as usize] += bytes;
        counts.calls[site as usize] += 1;
    });
}

pub(crate) fn hex_decode(bytes: usize) {
    update(|counts| {
        counts.hex_decodes += 1;
        counts.hex_input_bytes += bytes;
    });
}

pub(crate) fn index_order(count: usize) {
    update(|counts| {
        counts.index_orders += 1;
        counts.selected_index_bytes += count * std::mem::size_of::<usize>();
    });
}

struct Scope;
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

fn observe<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    assert!(
        !ACTIVE.with(|active| active.replace(true)),
        "nested encoding measurement"
    );
    COUNTS.with(|counts| counts.set(Counts::default()));
    let scope = Scope;
    let value = operation();
    drop(scope);
    (value, COUNTS.with(Cell::get))
}

fn report(case: &str, phase: &str, counts: Counts, output_bytes: usize) {
    let sites: serde_json::Map<_, _> = SITES
        .into_iter()
        .map(|site| {
            (
                format!("{site:?}"),
                serde_json::json!({
                    "bytes": counts.bytes[site as usize], "calls": counts.calls[site as usize],
                }),
            )
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "kind": "config_encoding_copy_sites", "case": case, "phase": phase,
            "observed_copy_bytes": counts.bytes.iter().sum::<usize>(), "sites": sites,
            "hex_decodes": counts.hex_decodes, "hex_input_bytes": counts.hex_input_bytes,
            "index_orders": counts.index_orders, "selected_index_bytes": counts.selected_index_bytes,
            "output_bytes": output_bytes, "total_copy_bytes": null, "elapsed_ns": null,
            "scope": "executed selected builder/compiled-encoding copy sites",
            "excludes": ["other extension codecs", "record framing", "non-builder transcripts", "HPKE internals", "allocator relocation", "metadata clones", "stack and header writes"],
        })
    );
}

fn compile(profile: TlsProfile) -> Arc<CompiledClientConfig> {
    CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility()).unwrap()
}

fn builder(config: &CompiledClientConfig) -> ClientHelloBuilder<'_> {
    ClientHelloBuilder::new(&config.hello_profile, "localhost").with_compiled(Some(config))
}

fn assert_reused(counts: Counts) {
    assert_eq!(counts.hex_decodes, 0, "reused static hex must stay decoded");
}

fn ech_config() -> Vec<u8> {
    let name = b"public.invalid";
    let mut contents = vec![1, 0, 32, 0, 32];
    contents.extend_from_slice(&[0x42; 32]);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 64, name.len() as u8]);
    contents.extend_from_slice(name);
    contents.extend_from_slice(&[0, 0]);
    let mut list = Vec::new();
    list.extend_from_slice(&((contents.len() + 4) as u16).to_be_bytes());
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    list.extend_from_slice(&contents);
    list
}

fn validate_output(output: &ClientHelloOutput) {
    assert_eq!(
        ClientHelloWire::parse(&output.message).unwrap().handshake,
        output.message
    );
}

#[test]
fn compiled_encoding_copy_sites_and_reuse_are_observable() {
    let mut ordered = presets::chrome_155();
    ordered.randomization = None;
    ordered.ech = Some(EchMode::Disabled);
    let mut shuffled = ordered.clone();
    shuffled.randomization = presets::chrome_155().randomization;
    let mut padded = ordered.clone();
    padded.padding = PaddingStrategy::FixedTarget {
        target_length: 4096,
    };
    // A raw immutable extension guarantees the cold decode probe exercises work.
    ordered
        .extensions
        .push(crate::profile::types::ExtensionSpec {
            extension_type: 0xfefa,
            source: ExtensionSource::RawBytes {
                data: "010203".into(),
            },
        });
    let cases = [
        ("editable", ordered),
        ("shuffle", shuffled),
        ("padding", padded),
    ];
    assert_eq!(cases.len(), 3);
    for (name, profile) in cases {
        let (config, cold) = observe(|| compile(profile));
        assert!(cold.hex_decodes > 0);
        report(name, "cold_compile", cold, 0);
        let template = ClientConfigTemplate::from_compiled(config.clone());
        let (cached, cache) = observe(|| template.compile().unwrap());
        assert!(Arc::ptr_eq(&cached, &config));
        assert_reused(cache);
        assert_eq!(cache.bytes.iter().sum::<usize>(), 0);
        report(name, "cached_plan", cache, 0);
        for _ in 0..2 {
            let (output, counts) = observe(|| builder(&config).build().unwrap());
            validate_output(&output);
            assert_reused(counts);
            assert!(counts.bytes[CopySite::FixedExtension as usize] > 0);
            assert_eq!(counts.index_orders, 1);
            assert!(
                counts.selected_index_bytes
                    <= config.profile().extensions.len() * std::mem::size_of::<usize>()
            );
            if name == "padding" {
                assert!(counts.bytes[CopySite::PaddingRebuild as usize] > 0);
            }
            report(name, "reused_build", counts, output.message.len());
        }
    }
}

#[test]
fn ech_psk_and_retry_copy_sites_observe_finalized_bytes() {
    let config = compile(presets::chrome_155());
    let ech = ech_config();
    let (first, first_counts) = observe(|| {
        builder(&config)
            .with_ech_config(ech.clone())
            .with_psk_offer(
                vec![0x55; 32],
                1,
                vec![0x66; 32],
                crate::crypto::hkdf::HkdfAlgorithm::Sha256,
                Vec::new(),
            )
            .build()
            .unwrap()
    });
    assert!(first.ech_offered);
    assert_reused(first_counts);
    assert_eq!(first_counts.bytes[CopySite::InnerPskIdentity as usize], 32);
    assert_eq!(first_counts.bytes[CopySite::InnerPskBinder as usize], 32);
    assert!(first_counts.bytes[CopySite::EchCiphertext as usize] > 0);
    validate_output(&first);
    report(
        "synthetic_inner_psk",
        "ech_ch1_builder",
        first_counts,
        first.message.len(),
    );
    // The retry fixture has no PSK: its CH1 is prepared outside the observed
    // CH2 scope. The independent endpoint tool measures a real peer's HRR.
    let mut first = builder(&config)
        .with_ech_config(ech.clone())
        .build()
        .unwrap();
    let wire = ClientHelloWire::parse(&first.message).unwrap();
    let mut retry = first.ech_retry_state.take().unwrap();
    let (second, second_counts) = observe(|| {
        builder(&config)
            .with_random(first.message[6..38].try_into().unwrap())
            .with_session_id(first.message[wire.session_id].to_vec())
            .with_grease_values(first.grease_values.clone())
            .with_extension_order(first.shuffled_extensions.clone())
            .with_ech_config(ech)
            .with_cookie(vec![1, 2, 3])
            .build_retry_with_key_pairs(&first.key_shares, Some(&mut retry))
            .unwrap()
    });
    assert!(second.ech_offered);
    assert_reused(second_counts);
    assert_eq!(
        second_counts.index_orders, 0,
        "CH2 must reuse CH1 index order"
    );
    assert!(second_counts.bytes[CopySite::EchCiphertext as usize] > 0);
    validate_output(&second);
    report(
        "ech",
        "retry_builder_with_retained_keys",
        second_counts,
        second.message.len(),
    );
}
