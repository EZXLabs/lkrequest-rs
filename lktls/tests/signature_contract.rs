use lktls::verify::certchain::{verify_certificate_verify, verify_server_key_exchange_signature};

fn signed_content() -> Vec<u8> {
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(&[0x42; 32]);
    content
}

#[test]
fn tls12_hash_pairs_allow_both_curves_but_tls13_schemes_bind_the_curve() {
    let content = signed_content();
    let cases: &[(u16, &[u8], &[u8], bool)] = &[
        (
            0x0403,
            include_bytes!("fixtures/signatures/p256.der"),
            include_bytes!("fixtures/signatures/p256-sha256.sig"),
            true,
        ),
        (
            0x0403,
            include_bytes!("fixtures/signatures/p384.der"),
            include_bytes!("fixtures/signatures/p384-sha256.sig"),
            false,
        ),
        (
            0x0503,
            include_bytes!("fixtures/signatures/p256.der"),
            include_bytes!("fixtures/signatures/p256-sha384.sig"),
            false,
        ),
        (
            0x0503,
            include_bytes!("fixtures/signatures/p384.der"),
            include_bytes!("fixtures/signatures/p384-sha384.sig"),
            true,
        ),
    ];
    for &(scheme, certificate, signature, tls13_valid) in cases {
        verify_server_key_exchange_signature(certificate, scheme, &content, signature).unwrap();
        assert_eq!(
            verify_certificate_verify(scheme, certificate, &[0x42; 32], signature).is_ok(),
            tls13_valid
        );
        let mut corrupted = signature.to_vec();
        let last = corrupted.last_mut().unwrap();
        *last ^= 1;
        assert!(
            verify_server_key_exchange_signature(certificate, scheme, &content, &corrupted)
                .is_err()
        );
        assert!(verify_server_key_exchange_signature(
            certificate,
            scheme,
            b"different message",
            signature
        )
        .is_err());
    }
}

#[test]
fn rsa_pss_works_in_both_versions_but_pkcs1_is_tls12_only() {
    use aws_lc_rs::{rand::SystemRandom, signature};
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let signer = signature::RsaKeyPair::from_pkcs8(&key.serialize_der()).unwrap();
    let content = signed_content();
    let cases: &[(u16, &dyn signature::RsaEncoding, bool)] = &[
        (0x0804, &signature::RSA_PSS_SHA256, true),
        (0x0805, &signature::RSA_PSS_SHA384, true),
        (0x0806, &signature::RSA_PSS_SHA512, true),
        (0x0401, &signature::RSA_PKCS1_SHA256, false),
    ];
    for &(scheme, encoding, tls13_valid) in cases {
        let mut signed = vec![0; signer.public_modulus_len()];
        signer
            .sign(encoding, &SystemRandom::new(), &content, &mut signed)
            .unwrap();
        verify_server_key_exchange_signature(certificate.der(), scheme, &content, &signed).unwrap();
        assert_eq!(
            verify_certificate_verify(scheme, certificate.der(), &[0x42; 32], &signed).is_ok(),
            tls13_valid
        );
        assert!(verify_server_key_exchange_signature(
            include_bytes!("fixtures/signatures/p256.der"),
            scheme,
            &content,
            &signed
        )
        .is_err());
    }
}

#[test]
fn tls12_p521_sha512_signatures_are_verified() {
    use aws_lc_rs::{rand::SystemRandom, signature};
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let signer = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &key.serialize_der(),
    )
    .unwrap();
    let content = signed_content();
    let sig = signer.sign(&SystemRandom::new(), &content).unwrap();
    verify_server_key_exchange_signature(cert.der(), 0x0603, &content, sig.as_ref()).unwrap();
    assert!(
        verify_server_key_exchange_signature(cert.der(), 0x0603, b"changed", sig.as_ref()).is_err()
    );
    assert!(verify_server_key_exchange_signature(
        include_bytes!("fixtures/signatures/p256.der"),
        0x0603,
        &content,
        sig.as_ref(),
    )
    .is_err());
}
