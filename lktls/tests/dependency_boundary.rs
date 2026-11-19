//! Keep the protocol core independent of transport runtimes and HTTP layers.

use std::process::Command;

#[test]
fn production_core_dependencies_do_not_cross_transport_or_http_boundaries() {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--locked",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("read Cargo's structured dependency metadata");
    assert!(
        output.status.success(),
        "Cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let package = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == env!("CARGO_PKG_NAME"))
        .expect("core package is present");
    let forbidden = [
        "tokio",
        "async-std",
        "smol",
        "quinn",
        "quinn-proto",
        "h2",
        "h3",
        "hyper",
        "http",
        "reqwest",
        "lkrequest",
        "lkh2",
        "lkh3",
        "lkquic",
        "lktls-quic",
    ];
    // Metadata resolves renamed dependencies and includes optional/target entries.
    let violations: Vec<_> = package["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|dependency| dependency["kind"] != "dev")
        .filter_map(|dependency| dependency["name"].as_str())
        .filter(|name| forbidden.contains(name))
        .collect();
    assert!(
        violations.is_empty(),
        "protocol-core dependencies cross the runtime/transport/HTTP boundary: {violations:?}"
    );
}
