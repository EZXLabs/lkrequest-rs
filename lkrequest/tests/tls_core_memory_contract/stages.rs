//! Representative client-only allocation stages, not a protocol outcome matrix.
//! Existing config, peer work, wire inspection and fixture generation are outside
//! scopes. Preexisting session memory keeps its original owner when consumed.

use std::sync::Arc;

use lktls::config::ConnectionInputs;
use lktls::connection::{ClientConnection, HandshakeProgress};
use lktls::extensions::{sni::Sni, Extension};
use lktls::handshake::{client_hello_wire::ClientHelloWire, server_hello::parse_server_hello};
use lktls::profile::types::ext_type;
use lktls::record::RecordHeader;
use lktls::session_store::InMemorySessionStore;

use super::{accounting::Owner, handshake, peer_output, send_client, Established, Peer};

fn plaintext_handshake(mut records: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::new();
    while !records.is_empty() {
        let header = RecordHeader::from_bytes(records[..5].try_into().unwrap());
        let end = 5 + usize::from(header.length);
        match header.content_type {
            22 => handshake.extend_from_slice(&records[5..end]),
            20 => assert_eq!(&records[5..end], &[1]),
            other => panic!("unexpected record type {other} in plaintext flight"),
        }
        records = &records[end..];
    }
    handshake
}

fn psk_first_flight() -> usize {
    let peer = Peer::new(false);
    let seed_owner = Owner::new();
    let store = seed_owner.enter(|| Arc::new(InMemorySessionStore::new()));
    drop(handshake(seed_owner, &peer, store.clone(), false));
    let seed_before = seed_owner.snapshot();
    assert!(seed_before.live > 0);

    let client_owner = Owner::new();
    let client = client_owner.enter(|| {
        let mut inputs = ConnectionInputs::new("localhost", 443);
        inputs.session_store = Some(store.clone());
        ClientConnection::from_compiled(peer.client.clone(), inputs).unwrap()
    });
    let start = client_owner.snapshot();
    let seed_after_start = seed_owner.snapshot();
    let wire = ClientHelloWire::parse(client.output()).unwrap();
    assert_eq!(
        wire.extensions.last().unwrap().extension_type,
        ext_type::PRE_SHARED_KEY
    );
    let output_bytes = client.output().len();
    let mut connection = Established {
        client,
        server: rustls::ServerConnection::new(peer.server.clone()).unwrap(),
    };
    send_client(client_owner, &mut connection);
    assert_eq!(
        connection.server.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    drop(connection);
    assert_eq!(client_owner.snapshot().live, 0);
    assert_eq!(client_owner.snapshot().blocks, 0);
    let cache_after_client_drop = seed_owner.snapshot().live;
    drop(store);
    assert_eq!(seed_owner.snapshot().live, 0);
    assert_eq!(seed_owner.snapshot().blocks, 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "client_encoding_stage", "stage": "tls13_real_psk_first_flight",
            "rust_allocations": start.allocations, "rust_reallocations": start.reallocations,
            "requested_bytes": start.requested, "new_client_peak_bytes": start.peak,
            "new_client_retained_bytes": start.live,
            "seed_owned_bytes_before": seed_before.live,
            "seed_owned_bytes_after_start": seed_after_start.live,
            "client_and_private_cache_retained_bytes": start.live + seed_after_start.live,
            "cache_bytes_after_client_drop": cache_after_client_drop,
            "all_owners_after_drop_bytes": 0, "first_flight_output_bytes": output_bytes,
            "peer_validated_resumption": true,
            "scope": "inputs_and_first_flight_excluding_authenticated_seed_and_shared_config",
            "c_backend_bytes": null, "copy_bytes": null, "elapsed_ns": null,
        })
    );
    start.allocations
}

fn hrr_second_flight() -> usize {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
    let peer = Peer::with_provider(false, provider);
    let owner = Owner::new();
    let mut connection = Established {
        client: owner.enter(|| {
            ClientConnection::from_compiled(
                peer.client.clone(),
                ConnectionInputs::new("localhost", 443),
            )
            .unwrap()
        }),
        server: rustls::ServerConnection::new(peer.server.clone()).unwrap(),
    };
    let first = ClientHelloWire::parse(connection.client.output()).unwrap();
    assert!(first
        .key_shares()
        .unwrap()
        .iter()
        .all(|share| share.group != 0x0018));
    send_client(owner, &mut connection);
    assert_eq!(
        owner.enter(|| connection.client.progress_handshake().unwrap()),
        HandshakeProgress::NeedInput
    );
    let incoming = peer_output(&mut connection.server);
    let retry = plaintext_handshake(&incoming);
    assert_eq!(retry[0], 2);
    let hello = parse_server_hello(&retry[4..]).unwrap();
    assert!(hello.is_hello_retry_request);
    assert_eq!(hello.extensions.selected_group, Some(0x0018));

    let before = owner.snapshot();
    owner.reset_peak();
    assert_eq!(
        owner.enter(|| connection.client.feed_bounded(&incoming)),
        incoming.len()
    );
    assert_eq!(
        owner.enter(|| connection.client.progress_handshake().unwrap()),
        HandshakeProgress::NeedOutput
    );
    let after = owner.snapshot();
    let second = ClientHelloWire::parse(&plaintext_handshake(connection.client.output())).unwrap();
    let shares = second.key_shares().unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].group, 0x0018);
    let output_bytes = connection.client.output().len();
    send_client(owner, &mut connection);
    assert_eq!(
        connection
            .server
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        rustls::NamedGroup::secp384r1
    );
    drop(connection);
    assert_eq!(owner.snapshot().live, 0);
    assert_eq!(owner.snapshot().blocks, 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "client_encoding_stage", "stage": "tls13_hrr_second_flight",
            "rust_allocations": after.allocations - before.allocations,
            "rust_reallocations": after.reallocations - before.reallocations,
            "requested_bytes": after.requested - before.requested,
            "retained_before_bytes": before.live, "retained_after_bytes": after.live,
            "stage_peak_live_bytes": after.peak,
            "all_owners_after_drop_bytes": 0, "second_flight_output_bytes": output_bytes,
            "scope": "feed_and_progress_including_parse_key_generation_and_record_framing",
            "peer_validated_requested_share": true,
            "c_backend_bytes": null, "copy_bytes": null, "elapsed_ns": null,
        })
    );
    after.allocations - before.allocations
}

fn ech_config(public_name: &str) -> Vec<u8> {
    // Same fixed X25519 offer fixture as tls_e2e_ech_rejection. The recipient
    // private key is intentionally absent: this case measures offer creation.
    let mut contents = vec![1];
    contents.extend_from_slice(&0x0020u16.to_be_bytes());
    contents.extend_from_slice(&32u16.to_be_bytes());
    contents.extend_from_slice(&[0x42; 32]);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
    contents.push(64);
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&[0, 0]);
    let mut config = Vec::new();
    config.extend_from_slice(&((contents.len() + 4) as u16).to_be_bytes());
    config.extend_from_slice(&0xfe0du16.to_be_bytes());
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    config
}

fn real_ech_first_flight() -> usize {
    const PUBLIC_NAME: &str = "public.ech-test.invalid";
    let peer = Peer::new(false);
    let config = ech_config(PUBLIC_NAME);
    let inputs = || {
        let mut inputs = ConnectionInputs::new("localhost", 443);
        inputs.ech_config_list = Some(config.clone());
        inputs
    };
    drop(ClientConnection::from_compiled(peer.client.clone(), inputs()).unwrap());
    let owner = Owner::new();
    let client =
        owner.enter(|| ClientConnection::from_compiled(peer.client.clone(), inputs()).unwrap());
    let start = owner.snapshot();
    let wire = ClientHelloWire::parse(client.output()).unwrap();
    let sni = wire
        .extensions
        .iter()
        .find(|e| e.extension_type == ext_type::SNI)
        .unwrap();
    let mut expected_sni = Vec::new();
    Sni {
        hostname: PUBLIC_NAME.into(),
    }
    .encode_payload(&mut expected_sni);
    assert_eq!(&wire.handshake[sni.payload.clone()], &expected_sni);
    let ech = wire
        .extensions
        .iter()
        .find(|e| e.extension_type == ext_type::ENCRYPTED_CLIENT_HELLO)
        .unwrap();
    let payload = &wire.handshake[ech.payload.clone()];
    assert_eq!(&payload[..8], &[0, 0, 1, 0, 1, 1, 0, 32]);
    assert!(payload.len() > 8 + 32 + 2 + 16);
    let output_bytes = client.output().len();
    drop(client);
    assert_eq!(owner.snapshot().live, 0);
    assert_eq!(owner.snapshot().blocks, 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "client_encoding_stage", "stage": "real_ech_first_flight",
            "rust_allocations": start.allocations, "rust_reallocations": start.reallocations,
            "requested_bytes": start.requested, "peak_bytes": start.peak,
            "pending_offer_retained_bytes": start.live,
            "all_owners_after_drop_bytes": 0, "first_flight_output_bytes": output_bytes,
            "scope": "inputs_config_blob_clone_inner_outer_hpke_snapshot_and_record_framing",
            "recipient_decryption_or_handshake_measured": false,
            "c_backend_bytes": null, "copy_bytes": null, "elapsed_ns": null,
        })
    );
    start.allocations
}

#[test]
#[ignore = "Deterministic PSK/HRR/ECH allocation stages; run explicitly with --ignored --nocapture"]
fn psk_hrr_and_real_ech_client_allocation_stages() {
    let allocations = [
        psk_first_flight(),
        hrr_second_flight(),
        real_ech_first_flight(),
    ];
    assert!(
        allocations.into_iter().all(|count| count > 0),
        "each measured stage must observe client allocations"
    );
}
