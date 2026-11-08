//! Generate reviewed TAI metadata from pinned Chromium certificate data.
//! Arguments: normalized metadata JSON, root_store.certs, output JSON.
use base64::Engine;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: generate_trust_anchor_catalog metadata.json root_store.certs output.json"
                .into(),
        );
    }
    let source: Value = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let mut entries: Vec<Value> =
        serde_json::from_value(source.get("entries").unwrap_or(&source).clone())?;
    let pem = std::fs::read_to_string(&args[2])?;
    let mut certificates = std::collections::HashMap::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block.split("-----END CERTIFICATE-----").next().unwrap();
        let der = base64::engine::general_purpose::STANDARD.decode(
            body.chars()
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>(),
        )?;
        let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der);
        let hash: String = sha
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        certificates.insert(hash, der);
    }
    for entry in &mut entries {
        let id = entry["id"].as_str().ok_or("entry requires id")?;
        lktls::trust_anchor::TrustAnchorId::from_hex(id)?;
        let sha = entry["certificate_sha256"]
            .as_str()
            .ok_or("entry requires certificate_sha256")?;
        if sha.len() != 64 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid certificate SHA256".into());
        }
        match entry["kind"].as_str() {
            Some("additional_certs") => {
                entry["anchor_identity"] = Value::Null;
                continue;
            }
            Some("trust_anchors") => {}
            _ => return Err("unsupported certificate metadata kind".into()),
        }
        let der = certificates
            .get(sha)
            .ok_or_else(|| format!("source certificate missing: {sha}"))?;
        let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(der)?;
        entry["anchor_identity"] = lktls::trust_anchor::anchor_identity(&anchor).into();
    }
    entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let output = serde_json::json!({
        "source": "chromium/157.0.8103.39/net/data/ssl/chrome_root_store",
        "root_store_version": 42,
        "source_sha256": {
            "root_store.textproto": "28386f4821e87d4d7abdfb2b90a28f938f27f1c16ded746133b2913c85027d5a",
            "root_store.certs": "653230aea8ce815391eb8a13bc22fb3a0243ba0f09395b61c319aa6d52348102",
        },
        "entries": entries,
    });
    std::fs::create_dir_all(std::path::Path::new(&args[3]).parent().unwrap())?;
    std::fs::write(
        &args[3],
        format!("{}\n", serde_json::to_string_pretty(&output)?),
    )?;
    Ok(())
}
