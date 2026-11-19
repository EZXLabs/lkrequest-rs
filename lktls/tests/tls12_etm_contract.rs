use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use aws_lc_rs::hmac;
use lktls::crypto::tls12_cipher::{CbcMacAlgorithm, CbcMacMode, Tls12CbcCipher};

#[test]
fn etm_wire_mac_covers_iv_ciphertext_header_and_sequence() {
    for key_len in [16, 32] {
        for (algorithm, hmac_algorithm) in [
            (
                CbcMacAlgorithm::HmacSha1,
                hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            ),
            (CbcMacAlgorithm::HmacSha256, hmac::HMAC_SHA256),
            (CbcMacAlgorithm::HmacSha384, hmac::HMAC_SHA384),
        ] {
            let key = vec![0x42; key_len];
            let mac_key = vec![0x24; algorithm.mac_len()];
            let cipher = Tls12CbcCipher::new_with_mode(
                &key,
                &mac_key,
                algorithm,
                CbcMacMode::EncryptThenMac,
            );
            for length in [0, 1, 15, 16, 17, 16384] {
                let plaintext = vec![0x53; length];
                let mut aad = [0; 13];
                aad[..8].copy_from_slice(&7u64.to_be_bytes());
                aad[8..11].copy_from_slice(&[23, 3, 3]);
                aad[11..].copy_from_slice(&(length as u16).to_be_bytes());
                let wire = cipher.encrypt(7, &aad, &plaintext).unwrap();
                let encrypted_len = 16 + (length / 16 + 1) * 16;
                assert_eq!(wire.len(), encrypted_len + algorithm.mac_len());

                // Independently inspect the RFC 7366 envelope; a symmetric roundtrip
                // alone would also pass if both endpoints used the wrong MAC input.
                let mut mac_input = aad.to_vec();
                mac_input[11..13].copy_from_slice(&(encrypted_len as u16).to_be_bytes());
                mac_input.extend_from_slice(&wire[..encrypted_len]);
                hmac::verify(
                    &hmac::Key::new(hmac_algorithm, &mac_key),
                    &mac_input,
                    &wire[encrypted_len..],
                )
                .unwrap();
                let mut inner = wire[16..encrypted_len].to_vec();
                if key_len == 16 {
                    cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &wire[..16])
                        .unwrap()
                        .decrypt_padded_mut::<NoPadding>(&mut inner)
                        .unwrap();
                } else {
                    cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &wire[..16])
                        .unwrap()
                        .decrypt_padded_mut::<NoPadding>(&mut inner)
                        .unwrap();
                }
                assert_eq!(&inner[..length], &plaintext);
                assert!(inner[length..]
                    .iter()
                    .all(|v| *v as usize == inner.len() - length - 1));
                assert_eq!(cipher.decrypt(&aad, &wire).unwrap(), plaintext);
                for position in [0, 16, wire.len() - 1] {
                    let mut bad = wire.clone();
                    bad[position] ^= 1;
                    assert!(cipher.decrypt(&aad, &bad).is_err());
                }
                for position in [0, 8, 9] {
                    let mut wrong_header = aad;
                    wrong_header[position] ^= 1;
                    assert!(cipher.decrypt(&wrong_header, &wire).is_err());
                }
                assert!(cipher.decrypt(&aad, &wire[..wire.len() - 1]).is_err());
            }
        }
    }
}

#[test]
fn etm_cannot_be_decoded_as_mac_then_encrypt_or_the_reverse() {
    let legacy = Tls12CbcCipher::new(&[0x42; 16], &[0x24; 20], CbcMacAlgorithm::HmacSha1);
    let etm = Tls12CbcCipher::new_with_mode(
        &[0x42; 16],
        &[0x24; 20],
        CbcMacAlgorithm::HmacSha1,
        CbcMacMode::EncryptThenMac,
    );
    let aad = [0; 13];
    let plaintext = b"different authenticated record layouts";
    assert!(legacy
        .decrypt(&aad, &etm.encrypt(0, &aad, plaintext).unwrap())
        .is_err());
    assert!(etm
        .decrypt(&aad, &legacy.encrypt(0, &aad, plaintext).unwrap())
        .is_err());
}
