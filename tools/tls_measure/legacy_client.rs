//! Identical standalone consumer for original/current client binary size.
//! No network, custom allocator, benchmark clock or candidate-only API.

use lktls::handshake::driver::{HandshakeConfig, HandshakeDriver, HandshakeOutput};
use lktls::profile::presets;
use lktls::verify::policy::VerificationPolicy;

fn main() {
    let hostname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost".into());
    let mut driver = HandshakeDriver::new(HandshakeConfig {
        profile: presets::chrome_144(),
        hostname,
        port: 443,
        verification_policy: VerificationPolicy::Strict,
        alps_payload: None,
        session_store: None,
        ech_config_list: None,
        custom_ca_anchors: None,
        keylog_callback: None,
        client_hello_callback: None,
        trust_anchor_observer: None,
    });
    let hello = driver.start().expect("build initial ClientHello");
    assert_eq!(hello.first(), Some(&22));
    driver.feed(&[]);
    assert!(matches!(driver.progress(), Ok(HandshakeOutput::NeedData)));
    println!("clienthello_bytes={}; awaiting_peer=true", hello.len());
}
