#[test]
fn browser_control_stream_agrees_with_independent_tshark_dissection() {
    let evidence: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/chrome_155_h3_control_capture.json")).unwrap();
    let bytes = hex::decode(evidence["raw_control_hex"].as_str().unwrap()).unwrap();
    let parsed = lkprofile::parse_h3_control_stream(&bytes).unwrap();
    assert_eq!(
        serde_json::json!(parsed
            .frames
            .iter()
            .map(|frame| frame.frame_type)
            .collect::<Vec<_>>()),
        evidence["tshark_frame_types"]
    );
    assert_eq!(
        serde_json::json!(parsed.settings),
        evidence["tshark_settings"]
    );
    let updates: Vec<_> = parsed
        .priority_updates
        .iter()
        .map(|update| {
            serde_json::json!({
                "frame_type": update.frame_type,
                "element_id": update.element_id,
                "field_value": std::str::from_utf8(update.field_value).unwrap(),
            })
        })
        .collect();
    assert_eq!(
        serde_json::json!(updates),
        evidence["tshark_priority_updates"]
    );
    assert_eq!(
        parsed.priority_updates.len(),
        2,
        "navigation and favicon updates"
    );
    assert_eq!(parsed.priority_updates[1].element_id, 4);
    assert_eq!(parsed.priority_updates[1].field_value, b"u=1, i");
    assert!(lkprofile::parse_h3_control_stream(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn public_library_control_stream_agrees_with_independent_tshark_dissection() {
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/library_chrome_155_h3_control_capture.json"
    ))
    .unwrap();
    let bytes = hex::decode(evidence["raw_control_hex"].as_str().unwrap()).unwrap();
    let parsed = lkprofile::parse_h3_control_stream(&bytes).unwrap();
    assert_eq!(
        serde_json::json!(parsed
            .frames
            .iter()
            .map(|frame| frame.frame_type)
            .collect::<Vec<_>>()),
        evidence["tshark_frame_types"]
    );
    assert_eq!(
        serde_json::json!(parsed.settings),
        evidence["tshark_settings"]
    );
    let updates: Vec<_> = parsed
        .priority_updates
        .iter()
        .map(|update| {
            serde_json::json!({
                "frame_type": update.frame_type,
                "element_id": update.element_id,
                "field_value": std::str::from_utf8(update.field_value).unwrap(),
            })
        })
        .collect();
    assert_eq!(
        serde_json::json!(updates),
        evidence["tshark_priority_updates"]
    );
    assert_eq!(
        parsed.priority_updates.len(),
        1,
        "this pre-fix capture lacks the favicon update"
    );
}

#[test]
fn corrected_public_library_updates_match_the_browser_targets_and_values() {
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/library_chrome_155_h3_control_fixed_capture.json"
    ))
    .unwrap();
    let browser: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/chrome_155_h3_control_capture.json")).unwrap();
    let bytes = hex::decode(evidence["raw_control_hex"].as_str().unwrap()).unwrap();
    let parsed = lkprofile::parse_h3_control_stream(&bytes).unwrap();
    assert_eq!(
        serde_json::json!(parsed
            .frames
            .iter()
            .map(|frame| frame.frame_type)
            .collect::<Vec<_>>()),
        evidence["tshark_frame_types"]
    );
    assert_eq!(
        serde_json::json!(parsed.settings),
        evidence["tshark_settings"]
    );
    let updates: Vec<_> = parsed
        .priority_updates
        .iter()
        .map(|update| {
            serde_json::json!({
                "frame_type": update.frame_type,
                "element_id": update.element_id,
                "field_value": std::str::from_utf8(update.field_value).unwrap(),
            })
        })
        .collect();
    assert_eq!(
        serde_json::json!(updates),
        evidence["tshark_priority_updates"]
    );
    assert_eq!(
        serde_json::json!(updates),
        browser["tshark_priority_updates"]
    );
    assert_eq!(
        &evidence["tshark_settings"].as_array().unwrap()[..4],
        &browser["tshark_settings"].as_array().unwrap()[..4]
    );
}
