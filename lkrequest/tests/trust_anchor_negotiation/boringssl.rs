use super::*;
use std::io::BufRead;

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "Tier-1: build tools/tai_interop and set TAI_BORINGSSL_PEER"]
async fn tai_boringssl_selects_trusted_credential_after_one_recovery() {
    let executable =
        std::env::var_os("TAI_BORINGSSL_PEER").expect("TAI_BORINGSSL_PEER is required");
    let mut root_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BoringSSL trusted root");
    let root_key = rcgen::KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = rcgen::CertifiedKey {
        cert: leaf_params
            .signed_by(
                &leaf_key,
                &rcgen::Issuer::from_params(&root_params, &root_key),
            )
            .unwrap(),
        signing_key: leaf_key,
    };
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BoringSSL untrusted fallback");
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let other = rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    };
    let directory = std::env::temp_dir().join(format!(
        "lkrequest-tai-boringssl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    struct Files(std::path::PathBuf);
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _files = Files(directory.clone());
    for (name, bytes) in [
        ("trusted.der", cert.cert.der().to_vec()),
        ("trusted.key", cert.signing_key.serialize_der()),
        ("fallback.der", other.cert.der().to_vec()),
        ("fallback.key", other.signing_key.serialize_der()),
    ] {
        std::fs::write(directory.join(name), bytes).unwrap();
    }
    let mut child = Child(
        std::process::Command::new(executable)
            .args(["trusted.der", "trusted.key", "fallback.der", "fallback.key"])
            .current_dir(&directory)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let port: u16 = line
        .trim()
        .strip_prefix("PORT ")
        .expect(&line)
        .parse()
        .unwrap();
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(root.der()).unwrap();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let client = Client::builder()
        .fingerprint(lifecycle::profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(root.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id: id.clone(),
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        client
            .session()
            .http1_only()
            .max_connections(1)
            .build()
            .post(&format!("https://localhost:{port}/test"))
            .body("payload")
            .collect_diagnostics(true)
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    let info = result.diagnostics().unwrap().trust_anchor.as_ref().unwrap();
    assert!(info.authenticated && info.recovered && info.matched_request);
    assert_eq!(
        info.verified_anchor.as_deref(),
        Some(anchor_identity(&anchor).as_str())
    );
    assert_eq!(info.requested_ids, vec![id]);
    assert!(!info.previous_attempt.as_ref().unwrap().matched_request);
    assert!(info
        .previous_attempt
        .as_ref()
        .unwrap()
        .failure
        .as_ref()
        .unwrap()
        .contains("UnknownIssuer"));
    assert_eq!(result.text().unwrap(), "ok");
    let mut remaining = String::new();
    output.read_to_string(&mut remaining).unwrap();
    assert!(child.0.wait().unwrap().success(), "{remaining}");
    assert_eq!(
        remaining
            .lines()
            .filter(|line| line.starts_with("HELLO "))
            .count(),
        2
    );
    assert!(
        remaining.lines().any(|line| line == "HELLO 00050481fd5901"),
        "{remaining}"
    );
    assert!(remaining.contains("REQUESTS 1"), "{remaining}");
}
