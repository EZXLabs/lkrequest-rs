use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use lktls::config::{
    Admission, CapabilityKind, CapabilityReason, ClientConfigTemplate, CompileError,
    CompileOptions, CompiledClientConfig, ConnectionInputs, SecurityPolicy, Transport,
};
use lktls::handshake::client_hello::ClientHelloBuilder;
use lktls::handshake::client_hello_wire::ClientHelloWire;
use lktls::handshake::driver::{HandshakeDriver, QuicHandshakeDriver};
use lktls::profile::{
    presets,
    types::{ext_type, ExtensionSource, ExtensionSpec, TlsProfile, TlsVersion},
};
use lktls::session_store::{ClientSession, ClientSessionStore, SessionStore, SessionTicketData};
use lktls::verify::policy::VerificationPolicy;

fn executable_profile(version: TlsVersion) -> TlsProfile {
    let mut profile = presets::chrome_144();
    profile.tls_min_version = version;
    profile.tls_max_version = version;
    profile.cipher_suites = if version == TlsVersion::Tls13 {
        vec![0x1301]
    } else {
        vec![0xc02f]
    };
    profile.supported_groups = vec![0x001d];
    profile.key_share_curves = vec![0x001d];
    profile.signature_algorithms = vec![0x0403, 0x0804];
    profile
        .extensions
        .retain(|e| matches!(e.extension_type, 0 | 10 | 13 | 16 | 43 | 51));
    profile.grease = Default::default();
    profile.randomization = None;
    profile.ech = None;
    profile.alps_protocols = None;
    profile
}

fn extension(profile: &mut TlsProfile, code: u16, payload: &str) {
    profile.extensions.retain(|e| e.extension_type != code);
    profile.extensions.push(ExtensionSpec {
        extension_type: code,
        source: ExtensionSource::RawBytes {
            data: payload.into(),
        },
    });
}

#[test]
fn complete_admission_is_versioned_and_does_not_filter_the_offer() {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let mut profile = executable_profile(version);
        profile.cipher_suites.insert(0, 0x1a1a);
        let config = CompiledClientConfig::compile(
            profile.clone(),
            Transport::Tcp,
            CompileOptions::default(),
        )
        .unwrap();
        assert!(config.capability_issues().is_empty());
        let mut driver =
            HandshakeDriver::from_compiled(config, ConnectionInputs::new("example.com", 443))
                .unwrap();
        let wire = ClientHelloWire::parse(&driver.start().unwrap()).unwrap();
        assert_eq!(wire.cipher_suites, profile.cipher_suites);
    }
}

#[test]
fn missing_capability_and_prohibited_policy_have_distinct_diagnostics() {
    let mut profile = executable_profile(TlsVersion::Tls12);
    profile.cipher_suites.push(0x002f);
    let CompileError::Capabilities(issues) =
        CompiledClientConfig::compile(profile.clone(), Transport::Tcp, CompileOptions::default())
            .unwrap_err()
    else {
        panic!("expected policy diagnostic")
    };
    assert!(issues
        .iter()
        .any(|i| i.code == 0x002f && i.reason == CapabilityReason::ProhibitedByPolicy));
    let historical = CompileOptions {
        security: SecurityPolicy::Historical,
        ..Default::default()
    };
    assert!(CompiledClientConfig::compile(profile.clone(), Transport::Tcp, historical).is_ok());
    profile.cipher_suites.push(0xdead);
    let compatible = CompiledClientConfig::compile(
        profile.clone(),
        Transport::Tcp,
        CompileOptions::compatibility(),
    )
    .unwrap();
    assert_eq!(compatible.profile().cipher_suites, profile.cipher_suites);
    assert!(compatible
        .capability_issues()
        .iter()
        .any(|i| i.kind == CapabilityKind::CipherSuite
            && i.code == 0xdead
            && i.reason == CapabilityReason::MissingImplementation));
    let modern_compatibility = CompileOptions {
        admission: Admission::Compatibility,
        ..Default::default()
    };
    assert!(CompiledClientConfig::compile(profile, Transport::Tcp, modern_compatibility).is_err());
}

#[test]
fn tls13_certificate_signature_schemes_are_not_handshake_signature_gaps() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    profile
        .signature_algorithms
        .extend([0x0401, 0x0501, 0x0601]);
    assert!(CompiledClientConfig::compile(
        profile.clone(),
        Transport::Tcp,
        CompileOptions::default()
    )
    .is_ok());
    profile.signature_algorithms.push(0x0603);
    assert!(CompiledClientConfig::compile(
        profile.clone(),
        Transport::Tcp,
        CompileOptions::default()
    )
    .is_ok());
    profile.signature_algorithms.push(0x0808);
    let CompileError::Capabilities(issues) =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default())
            .unwrap_err()
    else {
        panic!("expected missing Ed448 verifier")
    };
    assert!(issues.iter().any(|i| i.kind == CapabilityKind::Signature
        && i.code == 0x0808
        && i.version == Some(0x0304)));
}

#[test]
fn raw_capabilities_cannot_bypass_admission() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    extension(&mut profile, ext_type::SIGNATURE_ALGORITHMS, "00020403");
    assert!(matches!(
        CompiledClientConfig::compile(profile.clone(), Transport::Tcp, CompileOptions::default()),
        Err(CompileError::Invalid(_))
    ));
    profile.signature_algorithms = vec![0x0808];
    extension(&mut profile, ext_type::SIGNATURE_ALGORITHMS, "00020808");
    assert!(matches!(
        CompiledClientConfig::compile(profile.clone(), Transport::Tcp, CompileOptions::default()),
        Err(CompileError::Capabilities(_))
    ));
    extension(&mut profile, ext_type::SIGNATURE_ALGORITHMS, "00030403");
    assert!(matches!(
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default()),
        Err(CompileError::Invalid(_))
    ));
    let mut profile = executable_profile(TlsVersion::Tls13);
    extension(&mut profile, ext_type::KEY_SHARE, "0000");
    let compatible =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
            .unwrap();
    assert!(compatible
        .capability_issues()
        .iter()
        .any(|issue| issue.kind == CapabilityKind::Extension && issue.code == ext_type::KEY_SHARE));
}

#[test]
fn invalid_static_dependencies_fail_before_a_driver_exists() {
    for case in 0..6 {
        let mut profile = executable_profile(TlsVersion::Tls13);
        match case {
            0 => profile.tls_max_version = TlsVersion::Tls12,
            1 => profile.session_id_length = 33,
            2 => profile.compression_methods = vec![1],
            3 => profile.cipher_suites.clear(),
            4 => profile
                .extensions
                .retain(|e| e.extension_type != ext_type::KEY_SHARE),
            5 => profile.supported_groups = vec![0x0017],
            _ => unreachable!(),
        }
        assert!(
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default())
                .is_err(),
            "case {case}"
        );
    }
}

#[derive(Debug, Default)]
struct CountingStore(AtomicUsize);
impl ClientSessionStore for CountingStore {
    fn store_session(&self, _: &str, _: ClientSession) {
        panic!("unexpected store")
    }
    fn take_session(&self, _: &str) -> Option<ClientSession> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
}
impl SessionStore for CountingStore {
    fn store(&self, _: &str, _: SessionTicketData) {
        panic!("unexpected legacy store")
    }
    fn take(&self, _: &str) -> Option<SessionTicketData> {
        panic!("unexpected legacy take")
    }
    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        Some(self)
    }
}

#[test]
fn raw_alpn_overlay_conflicts_do_not_consume_a_session() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    profile.alpn_protocols = vec!["http/1.1".into()];
    extension(&mut profile, ext_type::ALPN, "0003026832");
    let config =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
            .unwrap();
    let store = Arc::new(CountingStore::default());
    let mut inputs = ConnectionInputs::new("example.com", 443);
    inputs.session_store = Some(store.clone());
    inputs.required_alpn = Some(vec!["http/1.1".into()]);
    let mut driver = HandshakeDriver::from_compiled(config, inputs).unwrap();
    assert!(driver
        .start()
        .unwrap_err()
        .to_string()
        .contains("raw ALPN conflicts"));
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}

#[test]
fn explicit_generated_override_conflicts_fail_before_session_selection() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    extension(&mut profile, ext_type::ALPN, "0003026832");
    let config =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
            .unwrap();
    let store = Arc::new(CountingStore::default());
    let mut inputs = ConnectionInputs::new("example.com", 443);
    inputs.session_store = Some(store.clone());
    inputs.hello_overrides.alpn_protocols = Some(vec!["http/1.1".into()]);
    inputs.hello_overrides.alps_protocols = Some(Vec::new());
    let mut driver = HandshakeDriver::from_compiled(config, inputs).unwrap();
    assert!(driver.start().is_err());
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}

#[test]
fn raw_alps_cannot_advertise_a_protocol_removed_by_an_overlay() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    profile.alpn_protocols = vec!["http/1.1".into()];
    extension(
        &mut profile,
        ext_type::APPLICATION_SETTINGS_NEW,
        "0003026832",
    );
    let config =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
            .unwrap();
    let store = Arc::new(CountingStore::default());
    let mut inputs = ConnectionInputs::new("example.com", 443);
    inputs.session_store = Some(store.clone());
    inputs.required_alpn = Some(vec!["http/1.1".into()]);
    let mut driver = HandshakeDriver::from_compiled(config, inputs).unwrap();
    assert!(driver
        .start()
        .unwrap_err()
        .to_string()
        .contains("raw ALPS conflicts"));
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}

#[test]
fn required_protocols_must_actually_be_advertised() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    profile
        .extensions
        .retain(|e| e.extension_type != ext_type::ALPN);
    let config =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default()).unwrap();
    let mut inputs = ConnectionInputs::new("example.com", 443);
    inputs.required_alpn = Some(config.profile().alpn_protocols.clone());
    let mut driver = HandshakeDriver::from_compiled(config, inputs).unwrap();
    assert!(driver
        .start()
        .unwrap_err()
        .to_string()
        .contains("required ALPN extension is absent"));
}

#[test]
fn unsupported_extensions_are_reported_and_grease_is_exempt() {
    for code in [34, 0xeeff, 0x1a1a] {
        let mut profile = executable_profile(if code == 34 {
            TlsVersion::Tls13
        } else {
            TlsVersion::Tls12
        });
        extension(&mut profile, code, "");
        let result = CompiledClientConfig::compile(
            profile,
            Transport::Tcp,
            CompileOptions {
                security: SecurityPolicy::Historical,
                ..Default::default()
            },
        );
        if code == 0x1a1a {
            assert!(result.is_ok());
        } else {
            let Err(CompileError::Capabilities(issues)) = result else {
                panic!("expected extension diagnostic")
            };
            assert!(issues
                .iter()
                .any(|i| i.kind == CapabilityKind::Extension && i.code == code));
        }
    }
}

#[test]
fn known_empty_extension_payloads_cannot_bypass_complete_admission() {
    for code in [18, 22, 23] {
        let mut profile = executable_profile(TlsVersion::Tls12);
        extension(&mut profile, code, "00");
        assert!(
            matches!(
                CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default()),
                Err(CompileError::Invalid(_))
            ),
            "code={code}"
        );
    }
}

#[test]
fn etm_and_ecdsa_cbc_are_executable_under_historical_policy() {
    let mut profile = executable_profile(TlsVersion::Tls12);
    profile.cipher_suites = vec![0xc009, 0xc00a, 0xc023, 0xc024];
    extension(&mut profile, 22, "");
    let config = CompiledClientConfig::compile(
        profile.clone(),
        Transport::Tcp,
        CompileOptions {
            security: SecurityPolicy::Historical,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(config.capability_issues().is_empty());
    assert_eq!(config.profile().cipher_suites, profile.cipher_suites);
    assert!(matches!(
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default()),
        Err(CompileError::Capabilities(_))
    ));
}

#[test]
fn extensions_without_a_legal_peer_selection_do_not_block_admission() {
    for (version, code) in [
        (TlsVersion::Tls13, 22),
        (TlsVersion::Tls12, 34),
        (TlsVersion::Tls12, 22),
    ] {
        let mut profile = executable_profile(version);
        extension(&mut profile, code, "");
        assert!(
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::default())
                .is_ok()
        );
    }
}

#[test]
fn templates_share_compilation_but_static_mutations_invalidate_it() {
    let template = ClientConfigTemplate::new(
        executable_profile(TlsVersion::Tls13),
        Transport::Tcp,
        CompileOptions::default(),
    );
    let config = template.compile().unwrap();
    let clones = (0..8)
        .map(|_| {
            let template = template.clone();
            std::thread::spawn(move || template.compile().unwrap())
        })
        .collect::<Vec<_>>();
    assert!(clones
        .into_iter()
        .all(|t| Arc::ptr_eq(&config, &t.join().unwrap())));
    let changed = template
        .clone()
        .verification_policy(VerificationPolicy::Insecure)
        .compile()
        .unwrap();
    assert!(!Arc::ptr_eq(&config, &changed));
    let changed_roots = template
        .clone()
        .custom_ca_anchors(Some(Arc::new(Vec::new())))
        .compile()
        .unwrap();
    assert!(!Arc::ptr_eq(&config, &changed_roots));
    let mut profile = template.profile().clone();
    profile.alpn_protocols = vec!["http/1.1".into()];
    let changed_profile = template.with_profile(profile).compile().unwrap();
    assert!(!Arc::ptr_eq(&config, &changed_profile));
    assert_eq!(config.profile().alpn_protocols, ["h2", "http/1.1"]);
}

fn erase_secrets(mut wire: ClientHelloWire) -> Vec<u8> {
    wire.handshake[6..38].fill(0);
    wire.handshake[wire.session_id.clone()].fill(0);
    for share in wire.key_shares().unwrap() {
        wire.handshake[share.key_exchange].fill(0);
    }
    wire.handshake
}

#[test]
fn compiled_encoding_preserves_raw_payloads_and_generates_fresh_connection_secrets() {
    let mut profile = executable_profile(TlsVersion::Tls13);
    extension(&mut profile, 0xeeff, "01020300fe");
    profile.extensions.push(ExtensionSpec {
        extension_type: ext_type::TRUST_ANCHOR_IDS,
        source: ExtensionSource::TrustAnchorIds {
            ids: vec!["010203".into()],
            shuffle: false,
        },
    });
    let expected = ClientHelloWire::parse(
        &ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .unwrap()
            .message,
    )
    .unwrap();
    let config =
        CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
            .unwrap();
    let mut first =
        HandshakeDriver::from_compiled(config.clone(), ConnectionInputs::new("example.com", 443))
            .unwrap();
    let mut second =
        HandshakeDriver::from_compiled(config, ConnectionInputs::new("example.com", 443)).unwrap();
    let first = ClientHelloWire::parse(&first.start().unwrap()).unwrap();
    let second = ClientHelloWire::parse(&second.start().unwrap()).unwrap();
    assert_ne!(&first.handshake[6..38], &second.handshake[6..38]);
    assert_ne!(
        &first.handshake[first.key_shares().unwrap()[0].key_exchange.clone()],
        &second.handshake[second.key_shares().unwrap()[0].key_exchange.clone()]
    );
    let expected = erase_secrets(expected);
    assert_eq!(erase_secrets(first), expected);
    assert_eq!(erase_secrets(second), expected);
}

#[test]
fn transport_is_bound_to_the_compiled_configuration() {
    let tcp = CompiledClientConfig::compile(
        executable_profile(TlsVersion::Tls13),
        Transport::Tcp,
        CompileOptions::default(),
    )
    .unwrap();
    assert!(QuicHandshakeDriver::from_compiled(
        tcp,
        ConnectionInputs::new("example.com", 443),
        vec![]
    )
    .is_err());
    let quic = CompiledClientConfig::compile(
        executable_profile(TlsVersion::Tls13),
        Transport::Quic,
        CompileOptions::default(),
    )
    .unwrap();
    assert!(HandshakeDriver::from_compiled(
        quic.clone(),
        ConnectionInputs::new("example.com", 443)
    )
    .is_err());
    let mut driver = QuicHandshakeDriver::from_compiled(
        quic,
        ConnectionInputs::new("example.com", 443),
        vec![1, 2],
    )
    .unwrap();
    let wire = ClientHelloWire::parse(&driver.start().unwrap()).unwrap();
    assert!(wire.session_id.is_empty());
    let params = wire
        .extensions
        .iter()
        .find(|e| e.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS)
        .unwrap();
    assert_eq!(&wire.handshake[params.payload.clone()], &[1, 2]);
}
