use super::*;

fn mock_connection() -> TcpConnection {
    TcpConnection::from_handshake(
        HandshakeResult {
            reader: RecordReader::new(),
            writer: RecordWriter::new(),
            negotiated_alpn: None,
            negotiated_cipher_suite: None,
            negotiated_version: None,
            peer_certificates: Vec::new(),
            post_handshake: None,
            session_ticket_ctx: None,
        },
        TlsClientHelloStyle::Generic,
    )
}

fn mock_post_handshake_state() -> PostHandshakeState {
    PostHandshakeState {
        server_app_secret: vec![0x22; 32],
        client_app_secret: vec![0x33; 32],
        hkdf_algorithm: crate::crypto::hkdf::HkdfAlgorithm::Sha256,
        aead_algorithm: crate::crypto::aead::AeadAlgorithm::Aes128Gcm,
        exporter_master_secret: vec![0x44; 32],
    }
}

#[test]
fn usage_limit_closes_tls12_after_the_accepted_prefix_without_discarding_it() {
    use crate::crypto::tls12_cipher::{Tls12GcmCipher, Tls12RecordCipher};
    let cipher =
        || Tls12RecordCipher::Gcm(Tls12GcmCipher::new(&[0x41; 16], &[0x32; 4], false).unwrap());
    let mut connection = mock_connection();
    connection.negotiated_version = Some(0x0303);
    connection.writer.set_tls12_keys(cipher());
    connection.writer.set_peer_record_size_limit(Some(64));
    connection.writer.set_sequence_for_test((1 << 24) - 3);
    assert_eq!(connection.write_application(&[0x51; 200]).unwrap(), 128);
    assert!(connection.is_closed());
    assert_eq!(connection.writer.remaining_records(), 0);
    let output = connection.output().to_vec();
    let mut peer = RecordReader::new();
    peer.set_tls12_keys(cipher());
    peer.set_sequence_for_test((1 << 24) - 3);
    peer.feed(&output);
    for _ in 0..2 {
        let record = peer.next_record().unwrap().unwrap();
        assert_eq!(record.content_type, content_type::APPLICATION_DATA);
        assert_eq!(record.payload, [0x51; 64]);
    }
    let close = peer.next_record().unwrap().unwrap();
    assert_eq!(close.content_type, content_type::ALERT);
    assert_eq!(close.payload, [1, 0]);
    assert!(peer.next_record().unwrap().is_none());
    assert!(connection.write_application(b"late").is_err());
    assert_eq!(connection.output(), output);
}

#[test]
fn control_work_budget_yields_without_losing_following_plaintext() {
    let mut connection = mock_connection();
    let warning = RecordWriter::new()
        .write_record(content_type::ALERT, &[1, 90])
        .unwrap();
    connection.feed(&warning.repeat(RECORD_WORK_BUDGET));
    connection.feed(
        &RecordWriter::new()
            .write_record(content_type::APPLICATION_DATA, b"next")
            .unwrap(),
    );
    assert_eq!(connection.process_read().unwrap(), ReadProgress::Yield);
    assert_eq!(connection.process_read().unwrap(), ReadProgress::Plaintext);
    assert_eq!(connection.plaintext(), b"next");
    connection.consume_plaintext(4);
    assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
}

#[test]
fn terminal_failure_preserves_one_alert_and_cannot_resume_processing() {
    let mut connection = mock_connection();
    connection.feed(&[24, 3, 3, 0, 1, 0]);
    assert!(connection.process_read().is_err());
    let alert = connection.output().to_vec();
    assert!(alert.ends_with(&[2, 10]));
    connection.feed(&[23, 3, 3, 0, 1, 7]);
    assert!(connection.process_read().is_err());
    assert_eq!(connection.output(), alert);
    assert!(connection.plaintext().is_empty());
    assert!(connection.write_application(b"late").is_err());
}

#[test]
fn repeated_requests_do_not_rotate_an_unused_browser_write_key() {
    for style in [
        TlsClientHelloStyle::ChromiumBoringssl,
        TlsClientHelloStyle::FirefoxNss,
    ] {
        let mut stream = mock_connection();
        stream.behavior.0 = style;
        stream.post_handshake = Some(mock_post_handshake_state());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        let first_secret = stream
            .post_handshake
            .as_ref()
            .unwrap()
            .client_app_secret
            .clone();
        let first_reply = stream.output().to_vec();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            first_secret
        );
        assert_eq!(stream.output(), first_reply);
    }
}

#[test]
fn chromium_key_update_limit_precedes_validation_without_rotating_rejected_keys() {
    let mut stream = mock_connection();
    stream.behavior.0 = TlsClientHelloStyle::ChromiumBoringssl;
    stream.post_handshake = Some(mock_post_handshake_state());
    for _ in 0..32 {
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 0])
            .unwrap();
    }
    let secret = stream
        .post_handshake
        .as_ref()
        .unwrap()
        .server_app_secret
        .clone();
    assert!(stream
        .handle_post_handshake_record(&[24, 0, 0, 1, 2])
        .is_err());
    assert_eq!(
        stream.post_handshake.as_ref().unwrap().server_app_secret,
        secret
    );
    assert_eq!(stream.consecutive_key_updates, 32);
    assert!(stream.output().ends_with(&[2, 10]));
}

#[test]
fn malformed_key_update_does_not_change_either_traffic_secret() {
    for style in [
        TlsClientHelloStyle::Generic,
        TlsClientHelloStyle::ChromiumBoringssl,
        TlsClientHelloStyle::FirefoxNss,
    ] {
        let enum_alert = if style == TlsClientHelloStyle::Generic {
            47
        } else {
            50
        };
        let cases = [
            (vec![24, 0, 0, 0], 50),
            (vec![24, 0, 0, 2, 1, 0], 50),
            (vec![24, 0, 0, 1, 2], enum_alert),
            (vec![24, 0, 0, 1, 0, 24, 0, 0, 1, 0], 10),
            (vec![24, 0, 0, 1, 0, 4], 10),
            (vec![24, 0, 0, 1, 0, 4, 0xff, 0xff, 0xff], 10),
            (vec![24, 0, 0, 1, 2, 24, 0, 0, 1, 0], enum_alert),
        ];
        for (message, expected) in cases {
            let mut stream = mock_connection();
            stream.behavior.0 = style;
            stream.post_handshake = Some(mock_post_handshake_state());
            assert!(stream.handle_post_handshake_record(&message).is_err());
            assert_eq!(
                stream.post_handshake.as_ref().unwrap().server_app_secret,
                vec![0x22; 32]
            );
            assert_eq!(
                stream.post_handshake.as_ref().unwrap().client_app_secret,
                vec![0x33; 32]
            );
            assert!(stream.output().ends_with(&[2, expected]));
            assert!(!stream.key_update_flush_pending);
        }
    }
}

#[test]
fn fragmented_key_update_changes_keys_only_at_the_completed_record_boundary() {
    let mut stream = mock_connection();
    stream.post_handshake = Some(mock_post_handshake_state());
    stream.handle_post_handshake_record(&[24, 0]).unwrap();
    assert_eq!(
        stream.post_handshake.as_ref().unwrap().server_app_secret,
        vec![0x22; 32]
    );
    stream.handle_post_handshake_record(&[0, 1, 0]).unwrap();
    let expected = crate::crypto::hkdf::hkdf_expand_label(
        crate::crypto::hkdf::HkdfAlgorithm::Sha256,
        &[0x22; 32],
        "traffic upd",
        &[],
        32,
    )
    .unwrap();
    assert_eq!(
        stream.post_handshake.as_ref().unwrap().server_app_secret,
        expected
    );
    assert_eq!(
        stream.post_handshake.as_ref().unwrap().client_app_secret,
        vec![0x33; 32]
    );
    assert!(stream.post_handshake_buf.is_empty());
    assert!(stream.write_buf.is_empty());
}

mod post_handshake_contract {
    use super::*;
    use crate::crypto::aead::{Aead, AeadAlgorithm};
    use crate::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};

    const STYLES: [TlsClientHelloStyle; 3] = [
        TlsClientHelloStyle::Generic,
        TlsClientHelloStyle::ChromiumBoringssl,
        TlsClientHelloStyle::FirefoxNss,
    ];

    fn traffic_key(secret: &[u8]) -> Aead {
        let key = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "key", &[], 16).unwrap();
        let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "iv", &[], 12).unwrap();
        Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap()
    }

    fn encrypted_connection(style: TlsClientHelloStyle) -> (TcpConnection, RecordWriter) {
        let state = mock_post_handshake_state();
        let mut peer = RecordWriter::new();
        peer.set_keys(traffic_key(&state.server_app_secret));
        let mut connection = mock_connection();
        connection.behavior.0 = style;
        connection.negotiated_version = Some(0x0304);
        connection
            .reader
            .set_keys(traffic_key(&state.server_app_secret));
        connection.reader.finish_tls13_handshake();
        connection
            .writer
            .set_keys(traffic_key(&state.client_app_secret));
        connection.post_handshake = Some(state);
        (connection, peer)
    }

    fn decrypt_record(key: &Aead, sequence: u64, bytes: &[u8]) -> (Vec<u8>, usize) {
        let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]])) + 5;
        let plaintext = key
            .decrypt(sequence, &bytes[..5], &bytes[5..length])
            .unwrap();
        (plaintext, length)
    }

    #[test]
    fn usage_limit_rotates_before_application_with_committed_old_key_update() {
        for style in STYLES {
            let (mut connection, _) = encrypted_connection(style);
            connection.writer.set_sequence_for_test((1 << 24) - 1);
            assert_eq!(connection.write_application(b"next").unwrap(), 4);
            let output = connection.output().to_vec();
            let (update, consumed) =
                decrypt_record(&traffic_key(&[0x33; 32]), (1 << 24) - 1, &output);
            assert_eq!(update, [24, 0, 0, 1, 0, content_type::HANDSHAKE]);
            let state = connection.post_handshake.as_ref().unwrap();
            let next =
                hkdf_expand_label(HkdfAlgorithm::Sha256, &[0x33; 32], "traffic upd", &[], 32)
                    .unwrap();
            assert_eq!(state.client_app_secret, next);
            assert_eq!(state.server_app_secret, [0x22; 32]);
            let (application, length) = decrypt_record(&traffic_key(&next), 0, &output[consumed..]);
            assert_eq!(application, b"next\x17");
            assert_eq!(consumed + length, output.len());
            assert_eq!(connection.writer.remaining_records(), (1 << 24) - 1);
            connection.consume_output(3);
            assert_eq!(connection.output(), &output[3..]);
            connection.consume_output(connection.output().len());
            assert!(!connection.is_closed());
        }
    }

    #[test]
    fn usage_limit_caps_application_prefix_at_negotiated_record_size() {
        let (mut connection, _) = encrypted_connection(TlsClientHelloStyle::Generic);
        connection.writer.set_peer_record_size_limit(Some(64));
        connection.writer.set_sequence_for_test((1 << 24) - 3);
        let input = vec![0x5a; 200];
        assert_eq!(connection.write_application(&input).unwrap(), 126);
        assert_eq!(connection.writer.remaining_records(), 1);
        let first = connection.output().to_vec();
        let (one, consumed) = decrypt_record(&traffic_key(&[0x33; 32]), (1 << 24) - 3, &first);
        let (two, length) =
            decrypt_record(&traffic_key(&[0x33; 32]), (1 << 24) - 2, &first[consumed..]);
        assert_eq!(
            one,
            [vec![0x5a; 63], vec![content_type::APPLICATION_DATA]].concat()
        );
        assert_eq!(two, one);
        assert_eq!(consumed + length, first.len());
        assert_eq!(connection.write_application(&input[126..]).unwrap(), 74);
        assert!(connection.output().starts_with(&first));
        let (update, consumed) = decrypt_record(
            &traffic_key(&[0x33; 32]),
            (1 << 24) - 1,
            &connection.output()[first.len()..],
        );
        assert_eq!(update, [24, 0, 0, 1, 0, content_type::HANDSHAKE]);
        let key = traffic_key(
            &connection
                .post_handshake
                .as_ref()
                .unwrap()
                .client_app_secret,
        );
        let (one, length) = decrypt_record(&key, 0, &connection.output()[first.len() + consumed..]);
        let (two, last) = decrypt_record(
            &key,
            1,
            &connection.output()[first.len() + consumed + length..],
        );
        assert_eq!(one.len(), 64);
        assert_eq!(two.len(), 12);
        assert_eq!(
            first.len() + consumed + length + last,
            connection.output().len()
        );
    }

    #[test]
    fn usage_limit_waits_for_output_capacity_without_rotating_twice() {
        let (mut connection, _) = encrypted_connection(TlsClientHelloStyle::Generic);
        assert!(
            connection
                .write_application(&vec![0x51; OUTPUT_LIMIT])
                .unwrap()
                > 0
        );
        let queued = connection.output().to_vec();
        connection.writer.set_sequence_for_test((1 << 24) - 1);
        // Model a smaller caller-owned output budget after the initial flight.
        let mut bounded = RecordBuffer::new(queued.len() + 10);
        assert_eq!(bounded.append(&queued), queued.len());
        connection.write_buf = bounded;
        assert_eq!(connection.write_application(b"next").unwrap(), 0);
        assert_eq!(connection.output(), queued);
        assert_eq!(connection.writer.remaining_records(), 1);
        assert_eq!(
            connection
                .post_handshake
                .as_ref()
                .unwrap()
                .client_app_secret,
            [0x33; 32]
        );
        connection.consume_output(queued.len());
        assert_eq!(connection.write_application(b"next").unwrap(), 4);
        let output = connection.output().to_vec();
        assert_eq!(connection.write_application(&[]).unwrap(), 0);
        assert_eq!(connection.output(), output);
        assert_eq!(connection.writer.remaining_records(), (1 << 24) - 1);
    }

    #[test]
    fn usage_limit_half_close_preserves_committed_output_on_inflight_key_update() {
        for style in STYLES {
            let (mut connection, mut peer) = encrypted_connection(style);
            connection.writer.set_sequence_for_test((1 << 24) - 2);
            assert_eq!(connection.write_application(b"last").unwrap(), 4);
            connection.start_close();
            assert!(connection.is_closed());
            assert_eq!(connection.writer.remaining_records(), 0);
            let committed = connection.output().to_vec();
            connection.consume_output(3);
            feed_record(
                &mut connection,
                &mut peer,
                content_type::HANDSHAKE,
                &[24, 0, 0, 1, 1],
            );
            assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
            assert_eq!(connection.output(), &committed[3..]);
            assert_eq!(
                connection
                    .post_handshake
                    .as_ref()
                    .unwrap()
                    .client_app_secret,
                [0x33; 32]
            );
            assert_ne!(
                connection
                    .post_handshake
                    .as_ref()
                    .unwrap()
                    .server_app_secret,
                [0x22; 32]
            );
            assert_eq!(connection.writer.remaining_records(), 0);
            peer.set_keys(traffic_key(
                &connection
                    .post_handshake
                    .as_ref()
                    .unwrap()
                    .server_app_secret,
            ));
            feed_record(
                &mut connection,
                &mut peer,
                content_type::APPLICATION_DATA,
                b"trailing",
            );
            assert_eq!(connection.process_read().unwrap(), ReadProgress::Plaintext);
            assert_eq!(connection.plaintext(), b"trailing");
            assert_eq!(connection.output(), &committed[3..]);
        }
    }

    #[test]
    fn half_close_never_appends_an_alert_or_discards_committed_output() {
        for remaining in [2, 100] {
            let (mut connection, mut peer) = encrypted_connection(TlsClientHelloStyle::Generic);
            connection
                .writer
                .set_sequence_for_test((1 << 24) - remaining);
            assert_eq!(connection.write_application(b"last").unwrap(), 4);
            connection.start_close();
            let committed = connection.output().to_vec();
            feed_record(
                &mut connection,
                &mut peer,
                content_type::HANDSHAKE,
                &[24, 0, 0, 1, 2],
            );
            assert!(connection.process_read().is_err());
            assert!(connection.failed);
            assert_eq!(connection.output(), committed);
            assert_eq!(connection.writer.remaining_records(), remaining - 2);
        }
    }

    fn feed_record(
        connection: &mut TcpConnection,
        peer: &mut RecordWriter,
        kind: u8,
        bytes: &[u8],
    ) {
        connection.feed(&peer.write_record(kind, bytes).unwrap());
    }

    fn ticket() -> Vec<u8> {
        vec![4, 0, 0, 14, 0, 0, 0x0e, 0x10, 0, 0, 0, 0, 0, 0, 1, 7, 0, 0]
    }

    fn expect_terminal_unexpected(connection: &mut TcpConnection) {
        let error = connection
            .process_read()
            .expect_err("invalid post-handshake input accepted");
        assert!(
            matches!(error, TlsError::LocalAlert { alert, .. }
            if alert.description == AlertDescription::UnexpectedMessage),
            "{error:?}"
        );
        assert!(connection.plaintext().is_empty());
        assert!(connection.is_closed());
        let alert = connection.output().to_vec();
        let mut peer_reader = RecordReader::new();
        peer_reader.set_keys(traffic_key(&[0x33; 32]));
        peer_reader.feed(&alert);
        let record = peer_reader.next_record().unwrap().unwrap();
        assert_eq!(record.content_type, content_type::ALERT);
        assert_eq!(record.payload, [2, 10]);
        assert!(peer_reader.next_record().unwrap().is_none());
        assert_eq!(connection.feed_bounded(&[0; 5]), 0);
        assert!(connection.process_read().is_err());
        assert!(connection.write_application(b"late").is_err());
        assert_eq!(connection.output(), alert);
    }

    #[test]
    fn tls13_rejects_application_interleaved_with_partial_control_message() {
        for style in STYLES {
            for message in [ticket(), vec![24, 0, 0, 1, 0]] {
                let (mut connection, mut peer) = encrypted_connection(style);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message[..2],
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::APPLICATION_DATA,
                    b"hidden",
                );
                expect_terminal_unexpected(&mut connection);
                assert_eq!(
                    connection
                        .post_handshake
                        .as_ref()
                        .unwrap()
                        .server_app_secret,
                    [0x22; 32]
                );
            }
        }
    }

    #[test]
    fn tls13_rejects_alert_interleaved_with_partial_control_message() {
        for style in STYLES {
            for alert in [[1, 0], [1, 90], [2, 40]] {
                let (mut connection, mut peer) = encrypted_connection(style);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &ticket()[..2],
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
                feed_record(&mut connection, &mut peer, content_type::ALERT, &alert);
                expect_terminal_unexpected(&mut connection);
                assert!(!connection.received_close_notify());
            }
        }
    }

    #[test]
    fn tls13_rejects_unexpected_post_handshake_message_types() {
        for style in STYLES {
            for kind in [0, 1, 2, 8, 11, 13, 15, 20, 254] {
                let (mut connection, mut peer) = encrypted_connection(style);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &[kind, 0, 0, 0],
                );
                expect_terminal_unexpected(&mut connection);
                assert!(connection.is_closed());
            }
        }
    }

    #[test]
    fn tls13_rejects_unknown_record_interleaved_with_partial_control_message() {
        for style in STYLES {
            let (mut connection, mut peer) = encrypted_connection(style);
            feed_record(
                &mut connection,
                &mut peer,
                content_type::HANDSHAKE,
                &ticket()[..2],
            );
            assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
            feed_record(&mut connection, &mut peer, 99, b"unknown");
            expect_terminal_unexpected(&mut connection);
        }
    }

    #[test]
    fn tls13_rejects_disallowed_message_before_waiting_for_its_body() {
        for style in STYLES {
            let (mut connection, mut peer) = encrypted_connection(style);
            feed_record(
                &mut connection,
                &mut peer,
                content_type::HANDSHAKE,
                &[20, 0, 0, 32],
            );
            expect_terminal_unexpected(&mut connection);
            assert!(connection.is_closed());
        }
    }

    #[test]
    fn tls13_accepts_tickets_fragmented_at_every_message_boundary() {
        let message = ticket();
        for style in STYLES {
            for split in 1..message.len() {
                let (mut connection, mut peer) = encrypted_connection(style);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message[..split],
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
                assert!(!connection.post_handshake_buf.is_empty());
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message[split..],
                );
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::APPLICATION_DATA,
                    b"ready",
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::Plaintext);
                assert_eq!(connection.plaintext(), b"ready");
                assert!(connection.post_handshake_buf.is_empty());
                assert!(connection.output().is_empty());
            }
        }
    }

    #[test]
    fn tls13_fragmented_key_update_rotates_after_its_final_record() {
        let message = [24, 0, 0, 1, 0];
        for style in STYLES {
            for split in 1..message.len() {
                let (mut connection, mut peer) = encrypted_connection(style);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message[..split],
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
                assert_eq!(
                    connection
                        .post_handshake
                        .as_ref()
                        .unwrap()
                        .server_app_secret,
                    [0x22; 32]
                );
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message[split..],
                );
                let next =
                    hkdf_expand_label(HkdfAlgorithm::Sha256, &[0x22; 32], "traffic upd", &[], 32)
                        .unwrap();
                peer.set_keys(traffic_key(&next));
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::APPLICATION_DATA,
                    b"new epoch",
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::Plaintext);
                assert_eq!(connection.plaintext(), b"new epoch");
                assert_eq!(
                    connection
                        .post_handshake
                        .as_ref()
                        .unwrap()
                        .server_app_secret,
                    next
                );
                assert_eq!(
                    connection
                        .post_handshake
                        .as_ref()
                        .unwrap()
                        .client_app_secret,
                    [0x33; 32]
                );
            }
        }
    }

    #[test]
    fn tls13_key_update_rejects_a_complete_or_partial_trailing_message() {
        for style in STYLES {
            for trailing in [ticket(), vec![4]] {
                let (mut connection, mut peer) = encrypted_connection(style);
                let mut message = vec![24, 0, 0, 1, 0];
                message.extend_from_slice(&trailing);
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &message,
                );
                expect_terminal_unexpected(&mut connection);
                assert_eq!(
                    connection
                        .post_handshake
                        .as_ref()
                        .unwrap()
                        .server_app_secret,
                    [0x22; 32]
                );
            }
        }
    }

    #[test]
    fn tls13_standalone_alerts_keep_existing_behavior() {
        for style in STYLES {
            let (mut connection, mut peer) = encrypted_connection(style);
            feed_record(&mut connection, &mut peer, content_type::ALERT, &[1, 0]);
            assert_eq!(connection.process_read().unwrap(), ReadProgress::PeerClosed);
            assert!(connection.received_close_notify());
            assert!(connection.output().is_empty());

            let (mut connection, mut peer) = encrypted_connection(style);
            feed_record(&mut connection, &mut peer, content_type::ALERT, &[1, 90]);
            assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
            assert!(!connection.is_closed());
            assert!(connection.output().is_empty());

            let (mut connection, mut peer) = encrypted_connection(style);
            feed_record(&mut connection, &mut peer, content_type::ALERT, &[2, 40]);
            assert!(matches!(connection.process_read(), Err(TlsError::Alert(_))));
            assert!(connection.is_closed());
            assert!(connection.output().is_empty());
        }
    }

    #[test]
    fn tls12_and_unknown_versions_keep_existing_post_handshake_policy() {
        for version in [None, Some(0x0303)] {
            let mut connection = mock_connection();
            connection.negotiated_version = version;
            let mut peer = RecordWriter::new();
            for kind in [2, 13, 20, 24, 254] {
                feed_record(
                    &mut connection,
                    &mut peer,
                    content_type::HANDSHAKE,
                    &[kind, 0, 0, 0],
                );
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
            }
            feed_record(
                &mut connection,
                &mut peer,
                content_type::HANDSHAKE,
                &[0, 0, 0, 0],
            );
            if version.is_some() {
                assert!(
                    matches!(connection.process_read(), Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == AlertDescription::NoRenegotiation)
                );
                assert!(connection.output().ends_with(&[2, 100]));
            } else {
                assert_eq!(connection.process_read().unwrap(), ReadProgress::NeedInput);
                assert!(connection.output().is_empty());
            }
        }
    }
}
