//! Strict verification primitives only. Fixture creation, result checks and
//! result destruction are outside each batch. Smoke never reads a clock.

#[path = "../../tools/tls_measure/clock.rs"]
mod clock;

use std::time::{Duration, SystemTime};

use lktls::error::{Result, TlsError};
use lktls::verify::{certchain::parse_trust_anchor_from_der, policy::VerificationPolicy};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls_pki_types::TrustAnchor;

const POLICY: VerificationPolicy = VerificationPolicy::Strict;
const TRANSCRIPT_HASH: [u8; 32] = [0x42; 32];

struct SignatureCase {
    name: &'static str,
    scheme: u16,
    certificate: &'static [u8],
    signature: &'static [u8],
    tls13_valid: bool,
}

const SIGNATURES: [SignatureCase; 4] = [
    SignatureCase {
        name: "p256_sha256",
        scheme: 0x0403,
        certificate: include_bytes!("fixtures/signatures/p256.der"),
        signature: include_bytes!("fixtures/signatures/p256-sha256.sig"),
        tls13_valid: true,
    },
    SignatureCase {
        name: "p384_sha256",
        scheme: 0x0403,
        certificate: include_bytes!("fixtures/signatures/p384.der"),
        signature: include_bytes!("fixtures/signatures/p384-sha256.sig"),
        tls13_valid: false,
    },
    SignatureCase {
        name: "p256_sha384",
        scheme: 0x0503,
        certificate: include_bytes!("fixtures/signatures/p256.der"),
        signature: include_bytes!("fixtures/signatures/p256-sha384.sig"),
        tls13_valid: false,
    },
    SignatureCase {
        name: "p384_sha384",
        scheme: 0x0503,
        certificate: include_bytes!("fixtures/signatures/p384.der"),
        signature: include_bytes!("fixtures/signatures/p384-sha384.sig"),
        tls13_valid: true,
    },
];

#[derive(Clone, Copy)]
enum Expected {
    Accepted,
    CurveBindingRejected,
}

impl Expected {
    fn check(self, result: Result<()>) {
        match self {
            Self::Accepted => result.expect("strict verification must succeed"),
            Self::CurveBindingRejected => match result {
                Err(TlsError::CertificateError(message)) => assert!(
                    message.contains("handshake signature verification failed"),
                    "unexpected rejection: {message}"
                ),
                other => panic!(
                    "TLS 1.3 curve binding must reject a valid cross-curve signature: {other:?}"
                ),
            },
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::CurveBindingRejected => "curve_binding_rejected",
        }
    }
}

fn signed_content() -> Vec<u8> {
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(&TRANSCRIPT_HASH);
    content
}

struct ChainFixture {
    chain: Vec<Vec<u8>>,
    anchors: Vec<TrustAnchor<'static>>,
    now: SystemTime,
}

fn certificate_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2036, 1, 1);
    params
}

impl ChainFixture {
    fn prepare() -> Self {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = certificate_params("verification-root.invalid");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::from_params(&root_params, &root_key);

        let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut intermediate_params = certificate_params("verification-intermediate.invalid");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, &intermediate_key);

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = certificate_params("verify.example.invalid");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();
        Self {
            chain: vec![leaf.der().to_vec(), intermediate.der().to_vec()],
            anchors: vec![parse_trust_anchor_from_der(root.der()).unwrap()],
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_830_297_600),
        }
    }

    fn verify(&self) -> Result<()> {
        POLICY.verify_certificate_chain(
            &self.chain,
            "verify.example.invalid",
            self.now,
            Some(&self.anchors),
        )
    }

    fn validate_fixture(&self) {
        self.verify().unwrap();
        assert!(
            POLICY
                .verify_certificate_chain(
                    &self.chain,
                    "wrong.example.invalid",
                    self.now,
                    Some(&self.anchors),
                )
                .is_err(),
            "hostname enforcement must remain strict"
        );
        assert!(
            POLICY
                .verify_certificate_chain(&self.chain, "verify.example.invalid", self.now, None,)
                .is_err(),
            "generated chain must require its explicit root"
        );
        assert!(
            POLICY
                .verify_certificate_chain(
                    &self.chain,
                    "verify.example.invalid",
                    SystemTime::UNIX_EPOCH,
                    Some(&self.anchors),
                )
                .is_err(),
            "validity enforcement must remain strict"
        );
    }
}

struct Row<'a> {
    case: &'a str,
    api: &'a str,
    expected: Expected,
    original_api: &'a str,
    fixture: serde_json::Value,
}

fn batch(
    timed: bool,
    batch_size: usize,
    expected: Expected,
    operation: impl Fn() -> Result<()>,
) -> Option<clock::Elapsed> {
    let mut results = Vec::with_capacity(batch_size);
    let start = timed.then(clock::ClockStart::start);
    for _ in 0..batch_size {
        results.push(std::hint::black_box(operation()));
    }
    let elapsed = start.map(clock::ClockStart::elapsed);
    assert_eq!(results.len(), batch_size);
    for result in results {
        expected.check(result);
    }
    elapsed
}

fn measure_row(
    row: Row<'_>,
    timed: bool,
    samples: usize,
    batch_size: usize,
    operation: impl Fn() -> Result<()>,
) -> usize {
    row.expected.check(operation());
    for sample in 0..samples {
        let elapsed = batch(timed, batch_size, row.expected, &operation);
        println!(
            "{}",
            serde_json::json!({
                "kind": "strict_verification_primitive", "case": row.case, "api": row.api,
                "policy": "strict", "expected": row.expected.name(), "sample": sample,
                "batch_size": batch_size, "mode": if timed { "measurement" } else { "smoke" },
                "wall_ns": elapsed.as_ref().map(|value| value.wall_ns),
                "thread_cpu_ns": elapsed.as_ref().and_then(|value| value.thread_cpu_ns),
                "thread_cpu_clock": clock::THREAD_CPU_CLOCK,
                "original_api_comparability": row.original_api, "fixture": row.fixture,
                "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                "package_version": env!("CARGO_PKG_VERSION"), "debug_assertions": cfg!(debug_assertions),
                "scope": "strict public verification API, loop and preallocated result writes",
                "excludes": ["fixture and signature generation", "fixture prevalidation", "result checks and destruction", "handshake parsing", "network and peer", "whole-handshake orchestration"],
                "copy_bytes": null, "allocations": null, "orchestration_cost": null,
            })
        );
    }
    samples
}

fn run(timed: bool, samples: usize, batch_size: usize, comparable_only: bool) -> usize {
    assert_eq!(POLICY, VerificationPolicy::Strict);
    assert!(samples > 0 && batch_size > 0);
    let content = signed_content();
    let mut rows = 0;
    for case in &SIGNATURES {
        if comparable_only && !case.tls13_valid {
            continue;
        }
        POLICY
            .verify_server_key_exchange_signature(
                case.certificate,
                case.scheme,
                &content,
                case.signature,
            )
            .unwrap();
        let mut corrupted = case.signature.to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(POLICY
            .verify_server_key_exchange_signature(
                case.certificate,
                case.scheme,
                &content,
                &corrupted
            )
            .is_err());
        assert!(POLICY
            .verify_server_key_exchange_signature(
                case.certificate,
                case.scheme,
                b"different message",
                case.signature
            )
            .is_err());
        if case.tls13_valid {
            assert!(POLICY
                .verify_certificate_verify(
                    case.scheme,
                    case.certificate,
                    &TRANSCRIPT_HASH,
                    &corrupted
                )
                .is_err());
        }
        for tls13 in [false, true] {
            let expected = if tls13 && !case.tls13_valid {
                Expected::CurveBindingRejected
            } else {
                Expected::Accepted
            };
            rows += measure_row(
                Row {
                    case: case.name,
                    api: if tls13 {
                        "verify_certificate_verify"
                    } else {
                        "verify_server_key_exchange_signature"
                    },
                    expected,
                    original_api: if !tls13 && !case.tls13_valid {
                        "correctness_changed; no original-success baseline for TLS1.2 cross-hash"
                    } else {
                        "same public call and expected outcome; compare identical fixtures"
                    },
                    fixture: serde_json::json!({"source": "committed OpenSSL signature fixtures", "scheme": case.scheme,
                    "certificate_bytes": case.certificate.len(), "signature_bytes": case.signature.len(),
                    "signed_message_bytes": content.len(), "tls12_input": "verification primitive content, not a parsed SKE flight"}),
                },
                timed,
                samples,
                batch_size,
                || {
                    if tls13 {
                        POLICY.verify_certificate_verify(
                            case.scheme,
                            case.certificate,
                            &TRANSCRIPT_HASH,
                            case.signature,
                        )
                    } else {
                        POLICY.verify_server_key_exchange_signature(
                            case.certificate,
                            case.scheme,
                            &content,
                            case.signature,
                        )
                    }
                },
            );
        }
    }
    let chain = ChainFixture::prepare();
    chain.validate_fixture();
    rows += measure_row(Row {
        case: "p256_root_intermediate_leaf", api: "verify_certificate_chain", expected: Expected::Accepted,
        original_api: "same public chain+hostname API; generated keys vary per process; compare matched shape/validity/anchor policy",
        fixture: serde_json::json!({"source": "rcgen generated before sampling", "sent_certificates": chain.chain.len(),
            "certificate_bytes": chain.chain.iter().map(Vec::len).collect::<Vec<_>>(), "custom_roots": chain.anchors.len(),
            "builtin_roots_also_searched": true, "verification_unix_seconds": chain.now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()}),
    }, timed, samples, batch_size, || chain.verify());
    rows
}

#[test]
fn strict_verification_smoke_checks_all_purposes_without_timing() {
    assert_eq!(run(false, 1, 2, false), 9);
}

#[test]
fn strict_verification_comparable_smoke_checks_success_paths_without_timing() {
    assert_eq!(run(false, 1, 2, true), 5);
}

#[test]
#[ignore = "Build release first, then run serially on an explicitly idle machine"]
fn strict_verification_wall_and_thread_cpu_batches() {
    assert_eq!(
        std::env::var("TLS_VERIFICATION_MEASURE_IDLE").as_deref(),
        Ok("1"),
        "TLS_VERIFICATION_MEASURE_IDLE=1 requires an idle machine"
    );
    if cfg!(debug_assertions) {
        panic!("verification timing requires release mode");
    }
    let samples: usize = std::env::var("TLS_VERIFICATION_MEASURE_SAMPLES")
        .map(|value| value.parse().unwrap())
        .unwrap_or(20);
    assert!(samples >= 20, "timing requires at least 20 samples");
    let batch_size: usize = std::env::var("TLS_VERIFICATION_MEASURE_BATCH")
        .map(|value| value.parse().unwrap())
        .unwrap_or(64);
    let comparable_only = std::env::var_os("TLS_VERIFICATION_MEASURE_COMPARABLE_ONLY").is_some();
    let rows_per_sample = if comparable_only { 5 } else { 9 };
    assert_eq!(
        run(true, samples, batch_size, comparable_only),
        samples * rows_per_sample
    );
}
