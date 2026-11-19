use lktls::handshake::tls13::Tls13Handshake;
use lktls::profile::presets;

#[test]
fn low_level_tls13_parser_does_not_discard_partial_headers() {
    for length in 1..4 {
        let mut handshake = Tls13Handshake::new(presets::chrome_144(), "localhost");
        handshake.build_client_hello().unwrap();
        assert!(handshake
            .process_handshake_record(&[2, 0, 0][..length])
            .is_err());
    }
}
