use std::fs::File;
use std::io::Read;
use std::path::Path;

use http::header::HeaderName;
use lkh2::policy::H2BehaviorConfig;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use super::{json, runtime::PresetRuntime, validation, ClientPreset};

/// Stable machine-readable reason for rejecting a profile document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresetErrorCode {
    InvalidJson,
    DuplicateKey,
    UnsupportedVersion,
    LegacyBundleIncomplete,
    UnknownField,
    InvalidProfile,
    ResourceLimit,
    FeatureUnavailable,
    UnsupportedBehavior,
    Io,
}

#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{code:?} at {path}: {message}")]
pub struct PresetError {
    pub code: PresetErrorCode,
    /// JSON Pointer, or `/` for an error affecting the whole document.
    pub path: String,
    pub message: String,
}

impl PresetError {
    pub(super) fn new(
        code: PresetErrorCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
    pub(super) fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(PresetErrorCode::InvalidProfile, path, message)
    }
    pub(super) fn limit(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(PresetErrorCode::ResourceLimit, path, message)
    }
}

/// Host-controlled budgets. A document cannot increase its own limits.
#[derive(Debug, Clone)]
pub struct PresetLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_container_entries: usize,
    pub max_string_bytes: usize,
    pub max_opaque_bytes: usize,
}

impl Default for PresetLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_nodes: 65_536,
            max_container_entries: 4096,
            max_string_bytes: 128 * 1024,
            max_opaque_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PresetLoader {
    pub limits: PresetLimits,
}

/// A validated, complete profile bundle. Metadata never affects execution.
#[derive(Debug, Clone)]
pub struct PresetDocument {
    name: String,
    metadata: Option<Value>,
    preset: ClientPreset,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleV2 {
    format: String,
    schema_version: u32,
    name: String,
    tls_profile: Value,
    quic_tls_profile: Value,
    h2_profile: Value,
    quic_profile: Value,
    header_order: Vec<String>,
    h3_header_order: Option<Vec<String>>,
    cookie_order: Option<Vec<String>>,
    runtime: PresetRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

impl PresetLoader {
    /// Migrate a legacy configuration snapshot using runtime settings supplied
    /// explicitly by the caller. Debug policy text is retained only as metadata.
    pub fn migrate_legacy_json(
        &self,
        input: &[u8],
        runtime: PresetRuntime,
    ) -> Result<PresetDocument, PresetError> {
        let mut value = json::parse(input, &self.limits)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| PresetError::invalid("/", "expected a legacy bundle object"))?;
        if object.contains_key("schema_version")
            || object.contains_key("runtime")
            || object
                .get("format")
                .is_some_and(|v| v != "lkrequest-profile-bundle-v1")
        {
            return Err(PresetError::new(
                PresetErrorCode::UnsupportedVersion,
                "/",
                "expected an unversioned or v1 legacy snapshot",
            ));
        }
        let snapshot = object.remove("policy_snapshot").unwrap_or(Value::Null);
        object.insert("format".into(), "lkrequest-profile-bundle".into());
        object.insert("schema_version".into(), 2.into());
        object.insert(
            "runtime".into(),
            serde_json::to_value(runtime).map_err(serialization_error)?,
        );
        if let Some(quic) = object.get_mut("quic_profile").filter(|v| !v.is_null()) {
            super::quic_json::complete_v2(quic);
            super::quic_json::convert(quic, true)?;
        }
        let metadata = object
            .entry("metadata")
            .or_insert_with(|| serde_json::json!({}));
        let metadata = metadata
            .as_object_mut()
            .ok_or_else(|| PresetError::invalid("/metadata", "metadata must be an object"))?;
        if metadata.contains_key("migration") {
            return Err(PresetError::invalid(
                "/metadata/migration",
                "migration metadata already exists",
            ));
        }
        metadata.insert("migration".into(), serde_json::json!({"runtime_supplied_by_caller": true, "legacy_policy_snapshot": snapshot}));
        self.from_json_slice(&serde_json::to_vec(&value).map_err(serialization_error)?)
    }

    pub fn from_json_str(&self, input: &str) -> Result<PresetDocument, PresetError> {
        self.from_json_slice(input.as_bytes())
    }

    pub fn from_json_file(&self, path: impl AsRef<Path>) -> Result<PresetDocument, PresetError> {
        let cap = self
            .limits
            .max_bytes
            .checked_add(1)
            .ok_or_else(|| PresetError::limit("/", "invalid host byte limit"))?;
        let file = File::open(path)
            .map_err(|e| PresetError::new(PresetErrorCode::Io, "/", e.to_string()))?;
        if !file
            .metadata()
            .map_err(|e| PresetError::new(PresetErrorCode::Io, "/", e.to_string()))?
            .is_file()
        {
            return Err(PresetError::new(
                PresetErrorCode::Io,
                "/",
                "profile path must be a regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(cap as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| PresetError::new(PresetErrorCode::Io, "/", e.to_string()))?;
        self.from_json_slice(&bytes)
    }

    pub fn from_json_slice(&self, input: &[u8]) -> Result<PresetDocument, PresetError> {
        let value = json::parse(input, &self.limits)?;
        let object = value
            .as_object()
            .ok_or_else(|| PresetError::invalid("/", "expected a bundle object"))?;
        if object.contains_key("policy_snapshot") || !object.contains_key("schema_version") {
            return Err(PresetError::new(PresetErrorCode::LegacyBundleIncomplete, "/", "legacy snapshot lacks executable runtime configuration; export or explicitly migrate to bundle v2"));
        }
        if value["format"] != "lkrequest-profile-bundle"
            || value["schema_version"].as_u64() != Some(2)
        {
            return Err(PresetError::new(
                PresetErrorCode::UnsupportedVersion,
                "/schema_version",
                "expected lkrequest-profile-bundle schema_version 2",
            ));
        }
        // Option fields must be present: null has explicit clearing/fallback semantics.
        for field in [
            "quic_tls_profile",
            "quic_profile",
            "h3_header_order",
            "cookie_order",
        ] {
            if !object.contains_key(field) {
                return Err(PresetError::invalid(
                    format!("/{field}"),
                    "required field is missing; use null explicitly",
                ));
            }
        }
        check_runtime_keys(&value)?;
        if object.get("metadata").is_some_and(|v| !v.is_object()) {
            return Err(PresetError::invalid(
                "/metadata",
                "metadata must be an object",
            ));
        }
        let bundle: BundleV2 = strict(value, "/")?;
        if bundle.runtime.version != 1 {
            return Err(PresetError::new(
                PresetErrorCode::UnsupportedVersion,
                "/runtime/version",
                "unsupported runtime version",
            ));
        }
        if bundle.runtime.h2_behavior.version != 1 {
            return Err(PresetError::new(
                PresetErrorCode::UnsupportedVersion,
                "/runtime/h2_behavior/version",
                "unsupported H2 behavior version",
            ));
        }
        if bundle.name.is_empty()
            || bundle.name.len() > 256
            || bundle.name.chars().any(char::is_control)
        {
            return Err(PresetError::invalid(
                "/name",
                "name must contain 1..256 bytes without control characters",
            ));
        }
        if bundle.metadata.as_ref().is_some_and(|v| !v.is_object()) {
            return Err(PresetError::invalid(
                "/metadata",
                "metadata must be an object",
            ));
        }
        if bundle.h2_profile.get("behavior").is_some() {
            return Err(PresetError::new(
                PresetErrorCode::UnknownField,
                "/h2_profile/behavior",
                "use runtime.h2_behavior",
            ));
        }
        let tls_profile = strict_profile(bundle.tls_profile, "/tls_profile")?;
        let quic_tls_profile = if bundle.quic_tls_profile.is_null() {
            None
        } else {
            Some(strict_profile(
                bundle.quic_tls_profile,
                "/quic_tls_profile",
            )?)
        };
        let mut h2_profile: lkh2::profile::H2Profile =
            strict_profile(bundle.h2_profile, "/h2_profile")?;
        h2_profile.behavior = Some(
            bundle
                .runtime
                .h2_behavior
                .build()
                .map_err(|e| PresetError::invalid("/runtime/h2_behavior", e))?,
        );
        let quic_profile = decode_quic(bundle.quic_profile)?;
        let preset = ClientPreset {
            tls_profile,
            quic_tls_profile,
            h2_profile,
            quic_profile,
            default_protocol_policy: Some(bundle.runtime.protocol.build()?),
            tls_session_cache_partition_policy: bundle.runtime.tls_session_cache_partition.into(),
            header_order: header_names(bundle.header_order, "/header_order")?,
            h3_header_order: bundle
                .h3_header_order
                .map(|v| header_names(v, "/h3_header_order"))
                .transpose()?,
            cookie_order: bundle.cookie_order,
        };
        validation::validate(&preset, &self.limits)?;
        Ok(PresetDocument {
            name: bundle.name,
            metadata: bundle.metadata,
            preset,
        })
    }
}

impl PresetDocument {
    pub fn from_json_str(input: &str) -> Result<Self, PresetError> {
        PresetLoader::default().from_json_str(input)
    }
    pub fn from_json_slice(input: &[u8]) -> Result<Self, PresetError> {
        PresetLoader::default().from_json_slice(input)
    }
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, PresetError> {
        PresetLoader::default().from_json_file(path)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn metadata(&self) -> Option<&Value> {
        self.metadata.as_ref()
    }
    pub fn preset(&self) -> &ClientPreset {
        &self.preset
    }
    pub fn into_preset(self) -> ClientPreset {
        self.preset
    }

    pub fn from_preset(
        name: impl Into<String>,
        preset: &ClientPreset,
    ) -> Result<Self, PresetError> {
        let document = Self {
            name: name.into(),
            metadata: None,
            preset: preset.clone(),
        };
        // Use the same validation and capability boundary for export and import.
        Self::from_json_str(&document.to_json_string()?)
    }

    pub fn to_json_string(&self) -> Result<String, PresetError> {
        let preset = &self.preset;
        let runtime = PresetRuntime {
            version: 1,
            protocol: super::runtime::ProtocolConfig::from_policy(
                &preset.default_protocol_policy.clone().unwrap_or_default(),
            )?,
            tls_session_cache_partition: preset.tls_session_cache_partition_policy.into(),
            h2_behavior: H2BehaviorConfig::from_behavior(&preset.h2_profile.behavior()).map_err(
                |e| {
                    PresetError::new(
                        PresetErrorCode::UnsupportedBehavior,
                        "/runtime/h2_behavior",
                        e,
                    )
                },
            )?,
        };
        let mut quic_profile =
            serde_json::to_value(&preset.quic_profile).map_err(serialization_error)?;
        if !quic_profile.is_null() {
            super::quic_json::complete_v2(&mut quic_profile);
            super::quic_json::convert(&mut quic_profile, true)?;
        }
        serde_json::to_string_pretty(&BundleV2 {
            format: "lkrequest-profile-bundle".into(),
            schema_version: 2,
            name: self.name.clone(),
            tls_profile: serde_json::to_value(&preset.tls_profile).map_err(serialization_error)?,
            quic_tls_profile: serde_json::to_value(&preset.quic_tls_profile)
                .map_err(serialization_error)?,
            h2_profile: serde_json::to_value(&preset.h2_profile).map_err(serialization_error)?,
            quic_profile,
            header_order: preset.header_order_strings(),
            h3_header_order: preset
                .h3_header_order
                .as_ref()
                .map(|v| v.iter().map(|h| h.as_str().to_owned()).collect()),
            cookie_order: preset.cookie_order.clone(),
            runtime,
            metadata: self.metadata.clone(),
        })
        .map_err(serialization_error)
    }
}

fn serialization_error(_: serde_json::Error) -> PresetError {
    PresetError::invalid("/", "profile serialization failed")
}

fn check_runtime_keys(value: &Value) -> Result<(), PresetError> {
    fn keys(value: &Value, path: &str, allowed: &[&str]) -> Result<(), PresetError> {
        if let Some(object) = value.as_object() {
            for key in object.keys() {
                if !allowed.contains(&key.as_str()) {
                    return Err(PresetError::new(
                        PresetErrorCode::UnknownField,
                        format!(
                            "{}/{}",
                            path.trim_end_matches('/'),
                            key.replace('~', "~0").replace('/', "~1")
                        ),
                        "unknown field",
                    ));
                }
            }
        }
        Ok(())
    }
    keys(
        value,
        "",
        &[
            "format",
            "schema_version",
            "name",
            "tls_profile",
            "quic_tls_profile",
            "h2_profile",
            "quic_profile",
            "header_order",
            "h3_header_order",
            "cookie_order",
            "runtime",
            "metadata",
        ],
    )?;
    let runtime = &value["runtime"];
    keys(
        runtime,
        "/runtime",
        &[
            "version",
            "protocol",
            "tls_session_cache_partition",
            "h2_behavior",
        ],
    )?;
    keys(
        &runtime["protocol"],
        "/runtime/protocol",
        &["intent", "acquisition", "upgrade", "fallback"],
    )?;
    let acquisition = &runtime["protocol"]["acquisition"];
    keys(
        acquisition,
        "/runtime/protocol/acquisition",
        if acquisition["type"] == "race" {
            &[
                "type",
                "enable_tcp",
                "enable_quic",
                "tcp_delay_ms",
                "quic_delay_ms",
                "only_when_h3_advertised",
            ]
        } else {
            &["type"]
        },
    )?;
    let h2 = &runtime["h2_behavior"];
    keys(
        h2,
        "/runtime/h2_behavior",
        &["version", "write", "flow_control", "hpack"],
    )?;
    keys(
        &h2["write"],
        "/runtime/h2_behavior/write",
        &[
            "split_headers",
            "split_data",
            "max_data_frame_payload",
            "send_goaway_on_close",
            "separate_end_stream_data",
        ],
    )?;
    keys(
        &h2["flow_control"],
        "/runtime/h2_behavior/flow_control",
        if h2["flow_control"]["type"] == "threshold" {
            &["type", "ratio"]
        } else {
            &["type"]
        },
    )
}

pub(super) fn strict<T: DeserializeOwned + Serialize>(
    value: Value,
    path: &str,
) -> Result<T, PresetError> {
    let mut unknown = None;
    let mut track = serde_path_to_error::Track::new();
    let de = serde_path_to_error::Deserializer::new(value.clone(), &mut track);
    let result: T = serde_ignored::deserialize(de, |p| {
        unknown.get_or_insert_with(|| ignored_pointer(&p));
    })
    .map_err(|e| {
        let mut pointer = path.trim_end_matches('/').to_owned();
        for segment in track.path().iter() {
            let key = match segment {
                serde_path_to_error::Segment::Seq { index } => index.to_string(),
                serde_path_to_error::Segment::Map { key } => key.clone(),
                serde_path_to_error::Segment::Enum { .. }
                | serde_path_to_error::Segment::Unknown => continue,
            };
            pointer.push('/');
            pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
        }
        PresetError::invalid(
            if pointer.is_empty() { "/" } else { &pointer },
            e.to_string(),
        )
    })?;
    if let Some(field) = unknown {
        return Err(PresetError::new(
            PresetErrorCode::UnknownField,
            format!("{}{field}", path.trim_end_matches('/')),
            "unknown field",
        ));
    }
    // Serde buffers internally tagged enums; ignored-field callbacks do not
    // always see their variant fields. Check their actual serialized shape too.
    check_tagged(
        &value,
        &serde_json::to_value(&result).map_err(serialization_error)?,
        path,
    )?;
    Ok(result)
}

fn ignored_pointer(path: &serde_ignored::Path<'_>) -> String {
    use serde_ignored::Path;
    match path {
        Path::Root => String::new(),
        Path::Seq { parent, index } => format!("{}/{index}", ignored_pointer(parent)),
        Path::Map { parent, key } => format!(
            "{}/{}",
            ignored_pointer(parent),
            key.replace('~', "~0").replace('/', "~1")
        ),
        Path::Some { parent }
        | Path::NewtypeStruct { parent }
        | Path::NewtypeVariant { parent } => ignored_pointer(parent),
    }
}

fn strict_profile<T: DeserializeOwned + Serialize>(
    value: Value,
    path: &str,
) -> Result<T, PresetError> {
    let profile: T = strict(value.clone(), path)?;
    let mut expected = serde_json::to_value(&profile).map_err(serialization_error)?;
    if path == "/quic_profile" {
        super::quic_json::complete_v2(&mut expected);
    }
    require_profile_fields(&value, &expected, path)?;
    Ok(profile)
}

fn require_profile_fields(input: &Value, expected: &Value, path: &str) -> Result<(), PresetError> {
    match (input, expected) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, value) in b {
                let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                let actual = a.get(key).ok_or_else(|| PresetError::invalid(&child, "complete v2 component field is missing; use an exported bundle as the starting point"))?;
                require_profile_fields(actual, value, &child)?;
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                require_profile_fields(a, b, &format!("{path}/{i}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_tagged(input: &Value, output: &Value, path: &str) -> Result<(), PresetError> {
    match (input, output) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, value) in a {
                let child = format!(
                    "{}/{}",
                    path.trim_end_matches('/'),
                    key.replace('~', "~0").replace('/', "~1")
                );
                if a.contains_key("type") && !b.contains_key(key) {
                    return Err(PresetError::new(
                        PresetErrorCode::UnknownField,
                        child,
                        "unknown variant field",
                    ));
                }
                if let Some(other) = b.get(key) {
                    check_tagged(value, other, &child)?;
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for (index, (a, b)) in a.iter().zip(b).enumerate() {
                check_tagged(a, b, &format!("{path}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn header_names(names: Vec<String>, path: &str) -> Result<Vec<HeaderName>, PresetError> {
    let mut seen = std::collections::HashSet::new();
    names
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                PresetError::invalid(format!("{path}/{i}"), "invalid ordinary header name")
            })?;
            if !seen.insert(header.clone()) {
                return Err(PresetError::invalid(
                    format!("{path}/{i}"),
                    "duplicate normalized header name",
                ));
            }
            Ok(header)
        })
        .collect()
}

fn decode_quic(mut value: Value) -> Result<Option<crate::QuicProfile>, PresetError> {
    if value.is_null() {
        return Ok(None);
    }
    #[cfg(not(feature = "quic-h3"))]
    {
        let _ = &mut value;
        Err(PresetError::new(
            PresetErrorCode::FeatureUnavailable,
            "/quic_profile",
            "this build requires the quic-h3 feature to load QUIC/H3 profiles",
        ))
    }
    #[cfg(feature = "quic-h3")]
    {
        super::quic_json::convert(&mut value, false)?;
        strict_profile(value, "/quic_profile").map(Some)
    }
}
