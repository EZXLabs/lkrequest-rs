use std::collections::HashMap;
use std::ffi::c_char;
use std::ptr;
use std::sync::OnceLock;

use crate::client::{parse_preset_name, preset_bundle};
use crate::error::FfiError;
use crate::panic::catch_status;

/// Load a complete v2 bundle. NULL/0 removes the bundle override and restores
/// the selected named preset. Explicit component overrides remain in effect.
/// Failure leaves the builder unchanged. Structured errors are available in
/// lk_error_get_diagnostics_json under preset_error (code, path, message).
#[no_mangle]
pub extern "C" fn lk_client_builder_set_preset_json(
    builder: *mut crate::handles::lk_client_builder_t,
    json_ptr: *const c_char,
    json_len: usize,
    out_err: *mut *mut crate::handles::lk_error_t,
) -> crate::abi::lk_status_t {
    catch_status(out_err, || unsafe {
        let builder =
            crate::handles::require_handle_mut::<crate::handles::ClientBuilderHandle, _>(builder)?;
        if json_ptr.is_null() && json_len == 0 {
            builder.state.preset_override = None;
            return Ok(());
        }
        let limit = lkrequest::preset::PresetLimits::default().max_bytes;
        if json_len > limit {
            return Err(FfiError::from_preset(lkrequest::preset::PresetError {
                code: lkrequest::preset::PresetErrorCode::ResourceLimit,
                path: "/".into(),
                message: "preset JSON exceeds 1 MiB".into(),
            }));
        }
        let bytes = crate::conv::read_bytes(json_ptr.cast::<u8>(), json_len, "preset JSON")?;
        let preset = lkrequest::preset::ClientPreset::from_json_slice(&bytes)
            .map_err(FfiError::from_preset)?;
        builder.state.preset_override = Some(preset);
        Ok(())
    })
}

/// Read only the caller-supplied UTF-8 file path and load a complete v2 bundle.
/// The file is bounded to 1 MiB; JSON cannot request additional file/network I/O.
#[no_mangle]
pub extern "C" fn lk_client_builder_set_preset_file(
    builder: *mut crate::handles::lk_client_builder_t,
    path_ptr: *const c_char,
    path_len: usize,
    out_err: *mut *mut crate::handles::lk_error_t,
) -> crate::abi::lk_status_t {
    catch_status(out_err, || unsafe {
        let builder =
            crate::handles::require_handle_mut::<crate::handles::ClientBuilderHandle, _>(builder)?;
        if path_len > 32 * 1024 {
            return Err(FfiError::resource_limit_exceeded(
                "preset path exceeds 32 KiB",
            ));
        }
        let path = crate::conv::read_string_parts(path_ptr, path_len, "preset path")?;
        if path.is_empty() || path.contains('\0') {
            return Err(FfiError::invalid_argument(
                "preset path is empty or contains NUL",
            ));
        }
        let preset =
            lkrequest::preset::ClientPreset::from_json_file(path).map_err(FfiError::from_preset)?;
        builder.state.preset_override = Some(preset);
        Ok(())
    })
}

/// Export a built-in preset as a complete, reloadable v2 document.
/// Query with NULL/0 output; out_json_len excludes NUL. Copy requires length+1
/// bytes; an undersized buffer returns RESOURCE_LIMIT_EXCEEDED without a partial
/// document. The caller owns the buffer. No network or file I/O is performed.
#[no_mangle]
pub extern "C" fn lk_preset_export_json(
    name_ptr: *const c_char,
    name_len: usize,
    out_json: *mut c_char,
    out_json_capacity: usize,
    out_json_len: *mut usize,
    out_err: *mut *mut crate::handles::lk_error_t,
) -> crate::abi::lk_status_t {
    catch_status(out_err, || unsafe {
        if !out_json.is_null() && out_json_capacity > 0 {
            *out_json = 0;
        }
        if out_json_len.is_null() {
            return Err(FfiError::invalid_argument("out_json_len is null"));
        }
        *out_json_len = 0;
        if out_json.is_null() && out_json_capacity > 0 {
            return Err(FfiError::invalid_argument(
                "out_json is null while capacity > 0",
            ));
        }
        if name_len > 256 {
            return Err(FfiError::invalid_argument("preset name exceeds 256 bytes"));
        }
        let name = crate::conv::read_string_parts(name_ptr, name_len, "preset name")?;
        let preset = preset_bundle(parse_preset_name(&name)?);
        let document = lkrequest::preset::PresetDocument::from_preset(name, &preset)
            .map_err(FfiError::from_preset)?;
        let json = document.to_json_string().map_err(FfiError::from_preset)?;
        *out_json_len = json.len();
        if out_json.is_null() {
            return Ok(());
        }
        if out_json_capacity <= json.len() {
            return Err(FfiError::resource_limit_exceeded(
                "preset output requires JSON length + 1 bytes",
            ));
        }
        ptr::copy_nonoverlapping(json.as_ptr(), out_json.cast::<u8>(), json.len());
        *out_json.add(json.len()) = 0;
        Ok(())
    })
}

fn preset_names() -> &'static [&'static str] {
    &[
        "chrome_131",
        "chrome_144",
        "chrome_145",
        "chrome_146",
        "chrome_147",
        "chrome_148",
        "chrome_149",
        "chrome_150",
        "chrome_151",
        "chrome_152",
        "chrome_153",
        "chrome_154",
        "chrome_155",
        "chrome_156",
        "chrome_157",
        "chrome_158",
        "firefox_133",
        "firefox_147",
        "firefox_156",
        "safari_18",
        "safari_26",
    ]
}

fn preset_list_json_bytes() -> &'static Vec<u8> {
    static LIST: OnceLock<Vec<u8>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut bytes = serde_json::to_vec(preset_names()).expect("serialize preset list");
        bytes.push(0);
        bytes
    })
}

fn preset_details_map() -> &'static HashMap<&'static str, Vec<u8>> {
    static DETAILS: OnceLock<HashMap<&'static str, Vec<u8>>> = OnceLock::new();
    DETAILS.get_or_init(|| {
        let mut map = HashMap::new();
        for &name in preset_names() {
            let preset = parse_preset_name(name).expect("known preset");
            let preset = preset_bundle(preset);
            let header_order = preset.header_order_strings();
            let h3_header_order = preset.h3_header_order.as_ref().map(|order| {
                order
                    .iter()
                    .map(|header| header.as_str().to_string())
                    .collect::<Vec<_>>()
            });
            let lkrequest::preset::ClientPreset {
                tls_profile,
                h2_profile,
                quic_profile,
                ..
            } = preset;
            let value = serde_json::json!({
                "name": name,
                "tls_profile": tls_profile,
                "h2_profile": h2_profile,
                "quic_profile": quic_profile,
                "header_order": header_order,
                "h3_header_order": h3_header_order,
            });
            let mut bytes = serde_json::to_vec(&value).expect("serialize preset detail");
            bytes.push(0);
            map.insert(name, bytes);
        }
        map
    })
}

#[no_mangle]
pub extern "C" fn lk_preset_list_json(out_json_ptr: *mut *const c_char) -> crate::abi::lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        let bytes = preset_list_json_bytes();
        *out_json_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_preset_get_detail_json(
    name_ptr: *const c_char,
    name_len: usize,
    out_json_ptr: *mut *const c_char,
    out_err: *mut *mut crate::handles::lk_error_t,
) -> crate::abi::lk_status_t {
    catch_status(out_err, || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        *out_json_ptr = ptr::null();
        let name = crate::conv::read_string_parts(name_ptr, name_len, "preset name")?;
        let bytes = preset_details_map()
            .get(name.as_str())
            .ok_or_else(|| FfiError::not_found(format!("preset not found: {name}")))?;
        *out_json_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}
