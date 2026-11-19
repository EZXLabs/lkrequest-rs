use aws_lc_rs::{rand::SystemRandom, signature};
use lktls::crypto::kx::{compute_shared_secret, generate_key_pair, KxGroup};
use lktls::verify::certchain::{verify_certificate_verify, verify_server_key_exchange_signature};

#[test]
fn p521_signed_certificate_chain_is_verified() {
    use lktls::verify::certchain::{parse_trust_anchor_from_der, verify_certificate_chain};
    let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
    let mut root_params = rcgen::CertificateParams::new(vec!["root.invalid".into()]).unwrap();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = root_params.self_signed(&root_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&root_params, &root_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let chain = vec![leaf.der().to_vec()];
    let anchors = vec![parse_trust_anchor_from_der(root.der()).unwrap()];
    verify_certificate_chain(
        &chain,
        "localhost",
        std::time::SystemTime::now(),
        Some(&anchors),
    )
    .unwrap();
    assert!(verify_certificate_chain(
        &chain,
        "wrong.invalid",
        std::time::SystemTime::now(),
        Some(&anchors)
    )
    .is_err());
    assert!(
        verify_certificate_chain(&chain, "localhost", std::time::SystemTime::now(), None).is_err()
    );
}

#[test]
fn p521_key_exchange_matches_and_rejects_invalid_points() {
    let group = KxGroup::from_code_point(0x0019).expect("P-521 must be executable");
    let alice = generate_key_pair(group).unwrap();
    let bob = generate_key_pair(group).unwrap();
    assert_eq!(alice.public_key.len(), 133);
    let alice_public = alice.public_key.clone();
    let secret = compute_shared_secret(alice, &bob.public_key).unwrap();
    assert_eq!(secret.len(), 66);
    assert_eq!(secret, compute_shared_secret(bob, &alice_public).unwrap());
    assert!(compute_shared_secret(generate_key_pair(group).unwrap(), &[0; 133]).is_err());
}

#[test]
fn p521_tls12_signatures_accept_all_three_hashes() {
    for (scheme, algorithm) in [
        (0x0403, &signature::ECDSA_P521_SHA256_ASN1_SIGNING),
        (0x0503, &signature::ECDSA_P521_SHA384_ASN1_SIGNING),
        (0x0603, &signature::ECDSA_P521_SHA512_ASN1_SIGNING),
    ] {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let signer = signature::EcdsaKeyPair::from_pkcs8(algorithm, &key.serialize_der()).unwrap();
        let message = b"TLS 1.2 ServerKeyExchange";
        let signed = signer.sign(&SystemRandom::new(), message).unwrap();
        verify_server_key_exchange_signature(certificate.der(), scheme, message, signed.as_ref())
            .unwrap();
        assert!(verify_server_key_exchange_signature(
            certificate.der(),
            scheme,
            b"changed",
            signed.as_ref()
        )
        .is_err());
    }
}

#[test]
fn p521_tls13_signature_is_bound_to_curve_and_hash() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(&[0x42; 32]);
    for (scheme, algorithm) in [
        (0x0403, &signature::ECDSA_P521_SHA256_ASN1_SIGNING),
        (0x0503, &signature::ECDSA_P521_SHA384_ASN1_SIGNING),
        (0x0603, &signature::ECDSA_P521_SHA512_ASN1_SIGNING),
    ] {
        let signer = signature::EcdsaKeyPair::from_pkcs8(algorithm, &key.serialize_der()).unwrap();
        let signed = signer.sign(&SystemRandom::new(), &content).unwrap();
        assert_eq!(
            verify_certificate_verify(scheme, certificate.der(), &[0x42; 32], signed.as_ref())
                .is_ok(),
            scheme == 0x0603
        );
        assert!(
            verify_certificate_verify(scheme, certificate.der(), &[0x43; 32], signed.as_ref())
                .is_err()
        );
    }
}
