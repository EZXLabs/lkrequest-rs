//! Controlled TLS 1.3 flights for TAI negative-path tests, never browser evidence.
use std::io::{Read, Write};

use aws_lc_rs::{digest, signature};
use lkrequest::lktls::{
    crypto::{
        aead::{Aead, AeadAlgorithm},
        hkdf::{hkdf_expand_label, hkdf_extract, HkdfAlgorithm},
        kx::{compute_shared_secret, generate_key_pair, KxGroup},
    },
    trust_anchor::{decode_list, encode_list, TrustAnchorId},
};

pub fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

pub fn read_hello(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 22);
    let mut out = header.to_vec();
    out.resize(
        5 + usize::from(u16::from_be_bytes([header[3], header[4]])),
        0,
    );
    stream.read_exact(&mut out[5..]).unwrap();
    out
}

pub fn ids(hello: &[u8]) -> Vec<TrustAnchorId> {
    let parsed = lkprofile::parse_client_hello(hello).unwrap();
    let payload = &parsed
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 0xca34)
        .unwrap()
        .data;
    decode_list(payload, true).unwrap()
}

#[derive(Default)]
pub struct Flight {
    pub available: Option<Vec<TrustAnchorId>>,
    pub bad_signature: bool,
    pub compressed: bool,
    pub certificate_flag: Option<Vec<u8>>,
    pub duplicate_ee: bool,
    pub alert: Option<u8>,
}

pub fn rejected_chain_flight(
    hello: &[u8],
    certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
    available: &[TrustAnchorId],
) -> Vec<u8> {
    flight(
        hello,
        certificate,
        &Flight {
            available: Some(available.to_vec()),
            ..Default::default()
        },
    )
}

// The transcript and CertificateVerify are valid unless deliberately corrupted.
// This peer stops before Finished so tests must fail at the intended boundary.
pub fn flight(
    hello_record: &[u8],
    certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
    options: &Flight,
) -> Vec<u8> {
    let hello = &hello_record[5..];
    let parsed = lkprofile::parse_client_hello(hello).unwrap();
    let shares = &parsed
        .extensions
        .iter()
        .find(|ext| ext.extension_type == 51)
        .unwrap()
        .data;
    let mut pos = 2;
    let peer = loop {
        let group = u16::from_be_bytes([shares[pos], shares[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([shares[pos + 2], shares[pos + 3]]));
        pos += 4;
        if group == 29 {
            break &shares[pos..pos + len];
        }
        pos += len;
    };
    let key = generate_key_pair(KxGroup::X25519).unwrap();
    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32];
    extensions.extend_from_slice(&key.public_key);
    let shared = compute_shared_secret(key, peer).unwrap();
    let mut sh_body = vec![3, 3];
    sh_body.extend_from_slice(&[0x51; 32]);
    let session_id = &hello[39..39 + usize::from(parsed.session_id_length)];
    sh_body.push(session_id.len() as u8);
    sh_body.extend_from_slice(session_id);
    sh_body.extend_from_slice(&[0x13, 1, 0]);
    sh_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&extensions);
    let sh = message(2, &sh_body);
    let mut transcript = hello.to_vec();
    transcript.extend_from_slice(&sh);
    let early = hkdf_extract(HkdfAlgorithm::Sha256, &[0; 32], &[0; 32]).unwrap();
    let handshake = early.derive_next(&shared).unwrap();
    let secret = handshake
        .derive_secret(
            "s hs traffic",
            digest::digest(&digest::SHA256, &transcript).as_ref(),
        )
        .unwrap();
    let key = hkdf_expand_label(HkdfAlgorithm::Sha256, &secret, "key", &[], 16).unwrap();
    let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, &secret, "iv", &[], 12).unwrap();
    let mut writer = lkrequest::lktls::record::writer::RecordWriter::new();
    let mut out = writer.write_record(22, &sh).unwrap();
    writer.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap());
    let mut ee = Vec::new();
    if let Some(ids) = &options.available {
        let payload = encode_list(ids).unwrap();
        let mut extension = vec![0xca, 0x34];
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend(payload);
        ee.extend_from_slice(&extension);
        if options.duplicate_ee {
            ee.extend(extension);
        }
    }
    let mut ee_body = (ee.len() as u16).to_be_bytes().to_vec();
    ee_body.extend(ee);
    let mut messages = message(8, &ee_body);
    if let Some(alert) = options.alert {
        out.extend(writer.write_record(22, &messages).unwrap());
        out.extend(writer.write_record(21, &[2, alert]).unwrap());
        return out;
    }
    let der = certificate.cert.der();
    let mut cert_extensions = Vec::new();
    if let Some(flag) = &options.certificate_flag {
        cert_extensions.extend_from_slice(&[0xca, 0x34]);
        cert_extensions.extend_from_slice(&(flag.len() as u16).to_be_bytes());
        cert_extensions.extend(flag);
    }
    let mut cert_body = vec![0];
    cert_body
        .extend_from_slice(&((der.len() + 5 + cert_extensions.len()) as u32).to_be_bytes()[1..]);
    cert_body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
    cert_body.extend_from_slice(der);
    cert_body.extend_from_slice(&(cert_extensions.len() as u16).to_be_bytes());
    cert_body.extend(cert_extensions);
    if options.compressed {
        let mut compressed = Vec::new();
        brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22)
            .write_all(&cert_body)
            .unwrap();
        let mut body = vec![0, 2];
        body.extend_from_slice(&(cert_body.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..]);
        body.extend(compressed);
        messages.extend(message(25, &body));
    } else {
        messages.extend(message(11, &cert_body));
    }
    transcript.extend_from_slice(&messages);
    let signer = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &certificate.signing_key.serialize_der(),
    )
    .unwrap();
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(digest::digest(&digest::SHA256, &transcript).as_ref());
    let signature = signer
        .sign(&aws_lc_rs::rand::SystemRandom::new(), &signed)
        .unwrap();
    let mut signature = signature.as_ref().to_vec();
    if options.bad_signature {
        signature[0] ^= 1;
    }
    let mut verify = vec![4, 3];
    verify.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    verify.extend(signature);
    messages.extend(message(15, &verify));
    out.extend(writer.write_record(22, &messages).unwrap());
    out
}
