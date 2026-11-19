use serde_json::Value;

use super::document::PresetError;

/// V2 writes every behavior knob explicitly, including fields omitted by the
/// native serializer. Native Default changes cannot reinterpret a saved bundle.
pub(super) fn complete_v2(value: &mut Value) {
    fn defaults(value: Option<&mut Value>, fields: &[(&str, Value)]) {
        if let Some(object) = value.and_then(Value::as_object_mut) {
            for (key, default) in fields {
                object.entry(*key).or_insert_with(|| default.clone());
            }
        }
    }
    defaults(
        Some(value),
        &[("initial_destination_connection_id_length", Value::Null)],
    );
    defaults(
        value.get_mut("transport_params"),
        &[
            ("max_udp_payload_size", Value::Null),
            ("max_datagram_frame_size", Value::Null),
            ("extra_transport_parameters", Value::Array(vec![])),
            ("transport_parameter_order", Value::Array(vec![])),
            ("shuffle_transport_parameters", false.into()),
            ("randomize_grease_shape", false.into()),
        ],
    );
    defaults(
        value.get_mut("h3"),
        &[
            ("priority_updates", Value::Array(vec![])),
            ("defer_qpack_stream_prefixes", false.into()),
            ("request_priority_updates", false.into()),
            ("accept_truncated_response_payloads", false.into()),
            ("wait_for_incomplete_response_frame_headers", false.into()),
            ("wait_for_response_after_upload_stop", false.into()),
            ("cancel_response_before_upload", false.into()),
            ("send_control_grease_frame", false.into()),
            ("chromium_grease", false.into()),
        ],
    );
    defaults(
        value.get_mut("packetization"),
        &[
            ("initial_mtu", Value::Null),
            ("initial_datagram_size", Value::Null),
            ("initial_frame_layout", Value::Null),
            ("disable_mtu_discovery", false.into()),
            ("initial_packet_chaos", false.into()),
            ("stop_before_matching_reset", false.into()),
            ("ack_obligation_only", false.into()),
            ("reset_finished_on_stop", false.into()),
            ("pto_single_probe_with_gap", false.into()),
            ("chrome_pto_timing", false.into()),
            ("reuse_rejected_0rtt_streams", false.into()),
            ("chrome_rtt_quantization", false.into()),
            ("chrome_loss_timing", false.into()),
            ("queue_pto_while_blocked", false.into()),
            ("discard_blocked_close", false.into()),
        ],
    );
    defaults(
        value.pointer_mut("/packetization/initial_frame_layout"),
        &[("packets", Value::Array(vec![]))],
    );
}

/// Only QUIC's u64/varint fields use decimal strings. MTUs, lengths and booleans
/// retain their native types; there is no heuristic conversion by numeric size.
pub(super) fn convert(value: &mut Value, exporting: bool) -> Result<(), PresetError> {
    let path = "/quic_profile";
    if let Some(tp) = value
        .get_mut("transport_params")
        .and_then(Value::as_object_mut)
    {
        for key in [
            "max_idle_timeout",
            "max_udp_payload_size",
            "initial_max_data",
            "initial_max_stream_data_bidi_local",
            "initial_max_stream_data_bidi_remote",
            "initial_max_stream_data_uni",
            "initial_max_streams_bidi",
            "initial_max_streams_uni",
            "active_connection_id_limit",
            "max_datagram_frame_size",
        ] {
            if let Some(v) = tp.get_mut(key) {
                number(v, exporting, &format!("{path}/transport_params/{key}"))?;
            }
        }
        if let Some(items) = tp
            .get_mut("transport_parameter_order")
            .and_then(Value::as_array_mut)
        {
            for (i, v) in items.iter_mut().enumerate() {
                number(
                    v,
                    exporting,
                    &format!("{path}/transport_params/transport_parameter_order/{i}"),
                )?;
            }
        }
        pairs(
            tp.get_mut("extra_transport_parameters"),
            false,
            exporting,
            &format!("{path}/transport_params/extra_transport_parameters"),
        )?;
    }
    if let Some(h3) = value.get_mut("h3").and_then(Value::as_object_mut) {
        for key in [
            "qpack_max_table_capacity",
            "qpack_blocked_streams",
            "max_field_section_size",
        ] {
            if let Some(v) = h3.get_mut(key) {
                number(v, exporting, &format!("{path}/h3/{key}"))?;
            }
        }
        pairs(
            h3.get_mut("settings"),
            true,
            exporting,
            &format!("{path}/h3/settings"),
        )?;
        pairs(
            h3.get_mut("priority_updates"),
            false,
            exporting,
            &format!("{path}/h3/priority_updates"),
        )?;
    }
    if let Some(packets) = value
        .pointer_mut("/packetization/initial_frame_layout/packets")
        .and_then(Value::as_array_mut)
    {
        for (i, packet) in packets.iter_mut().enumerate() {
            let packet_path = format!("{path}/packetization/initial_frame_layout/packets/{i}");
            if let Some(v) = packet.get_mut("packet_number") {
                number(v, exporting, &format!("{packet_path}/packet_number"))?;
            }
            if let Some(frames) = packet.get_mut("frames").and_then(Value::as_array_mut) {
                for (j, frame) in frames.iter_mut().enumerate() {
                    if let Some(v) = frame.get_mut("offset") {
                        number(v, exporting, &format!("{packet_path}/frames/{j}/offset"))?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn pairs(
    value: Option<&mut Value>,
    both: bool,
    exporting: bool,
    path: &str,
) -> Result<(), PresetError> {
    if let Some(items) = value.and_then(Value::as_array_mut) {
        for (i, pair) in items.iter_mut().enumerate() {
            if let Some(pair) = pair.as_array_mut() {
                for (j, v) in pair.iter_mut().take(if both { 2 } else { 1 }).enumerate() {
                    number(v, exporting, &format!("{path}/{i}/{j}"))?;
                }
            }
        }
    }
    Ok(())
}

fn number(value: &mut Value, exporting: bool, path: &str) -> Result<(), PresetError> {
    if value.is_null() {
        return Ok(());
    }
    let integer = if exporting {
        value.as_u64()
    } else {
        value.as_str().and_then(|s| {
            if s.is_empty()
                || (s.len() > 1 && s.starts_with('0'))
                || !s.bytes().all(|b| b.is_ascii_digit())
            {
                None
            } else {
                s.parse::<u64>().ok()
            }
        })
    }
    .filter(|n| *n < (1_u64 << 62))
    .ok_or_else(|| {
        PresetError::invalid(
            path,
            "expected a canonical decimal QUIC integer string in 0..2^62-1",
        )
    })?;
    *value = if exporting {
        Value::String(integer.to_string())
    } else {
        integer.into()
    };
    Ok(())
}
