//! Immutable client configuration and executable capability admission.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use rustls_pki_types::TrustAnchor;

mod capability;
pub(crate) mod encoding;
mod metadata;
mod overlay;
use capability::capability_issues;
pub use overlay::ClientHelloOverrides;
pub(crate) use overlay::ConnectionOverlay;

use crate::error::TlsError;
use crate::handshake::client_hello::{decode_hex, ClientHelloBuilder};
use crate::profile::types::{ext_type, ExtensionSource, ExtensionSpec, TlsProfile, TlsVersion};
use crate::verify::policy::VerificationPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
}

/// Admission never removes advertised values from a fingerprint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Admission {
    #[default]
    Complete,
    /// Preserve capability gaps and reject unsupported peer selections later.
    Compatibility,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecurityPolicy {
    /// TLS 1.2/1.3, forward secrecy and AEAD record protection.
    #[default]
    Modern,
    /// Allow implemented historical suites without changing their wire order.
    Historical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityKind {
    Version,
    CipherSuite,
    KeyExchangeGroup,
    Signature,
    CertificateCompression,
    Extension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityReason {
    MissingImplementation,
    ProhibitedByPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityIssue {
    pub kind: CapabilityKind,
    pub code: u16,
    pub version: Option<u16>,
    pub reason: CapabilityReason,
}

#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    pub admission: Admission,
    pub security: SecurityPolicy,
    pub verification: VerificationPolicy,
    pub custom_ca_anchors: Option<Arc<Vec<TrustAnchor<'static>>>>,
}

/// Per-attempt identity and services; never retained in a shared configuration.
#[derive(Clone, Default)]
pub struct ConnectionInputs {
    pub hostname: String,
    pub port: u16,
    /// Require this exact ALPN offer without rewriting raw extension payloads.
    pub required_alpn: Option<Vec<String>>,
    /// Explicit generated extension changes for this connection only.
    pub hello_overrides: ClientHelloOverrides,
    pub alps_payload: Option<Vec<u8>>,
    pub session_store: Option<Arc<dyn crate::session_store::SessionStore>>,
    pub ech_config_list: Option<Vec<u8>>,
    pub keylog_callback: Option<crate::KeyLogCallback>,
    pub client_hello_callback: Option<crate::ClientHelloCallback>,
    pub trust_anchor_observer: Option<crate::trust_anchor::TrustAnchorObserver>,
}

impl ConnectionInputs {
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            ..Self::default()
        }
    }
}

impl CompileOptions {
    /// Existing client admission and security behavior, with diagnostics.
    pub fn compatibility() -> Self {
        Self {
            admission: Admission::Compatibility,
            security: SecurityPolicy::Historical,
            ..Self::default()
        }
    }
}

/// Deferred compilation for infallible compatibility builders. Clones share
/// immutable inputs and one compilation result, including validation errors.
#[derive(Debug, Clone)]
pub struct ClientConfigTemplate {
    profile: Arc<TlsProfile>,
    transport: Transport,
    options: CompileOptions,
    compiled: Arc<OnceLock<Result<Arc<CompiledClientConfig>, CompileError>>>,
}

impl ClientConfigTemplate {
    pub fn new(
        profile: impl Into<Arc<TlsProfile>>,
        transport: Transport,
        options: CompileOptions,
    ) -> Self {
        Self {
            profile: profile.into(),
            transport,
            options,
            compiled: Arc::default(),
        }
    }

    pub fn from_compiled(config: Arc<CompiledClientConfig>) -> Self {
        Self {
            profile: config.profile.clone(),
            transport: config.transport,
            options: config.options.clone(),
            compiled: Arc::new(OnceLock::from(Ok(config))),
        }
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.profile
    }

    pub fn shared_profile(&self) -> Arc<TlsProfile> {
        self.profile.clone()
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    pub fn with_profile(mut self, profile: impl Into<Arc<TlsProfile>>) -> Self {
        self.profile = profile.into();
        self.compiled = Arc::default();
        self
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        if self.options.verification != policy {
            self.options.verification = policy;
            self.compiled = Arc::default();
        }
        self
    }

    pub fn custom_ca_anchors(mut self, anchors: Option<Arc<Vec<TrustAnchor<'static>>>>) -> Self {
        let same = match (&self.options.custom_ca_anchors, &anchors) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            self.options.custom_ca_anchors = anchors;
            self.compiled = Arc::default();
        }
        self
    }

    pub fn compile(&self) -> Result<Arc<CompiledClientConfig>, CompileError> {
        self.compiled
            .get_or_init(|| {
                CompiledClientConfig::compile(
                    self.profile.clone(),
                    self.transport,
                    self.options.clone(),
                )
            })
            .clone()
    }

    /// Prepare a TAI recovery attempt. A unique generated TAI source shares this
    /// template, including raw ALPN/ALPS. `profile()` remains the base profile;
    /// requested IDs live in the returned overrides. Raw TAI profiles
    /// preserve the legacy profile replacement behavior.
    /// The caller owns session invalidation and attempt-specific observers.
    pub fn trust_anchor_recovery(
        &self,
        ids: Vec<crate::trust_anchor::TrustAnchorId>,
        overrides: &ClientHelloOverrides,
    ) -> crate::error::Result<(Self, ClientHelloOverrides)> {
        let mut overrides = overrides.clone();
        if self.compile()?.metadata.generated_tai_recovery {
            crate::trust_anchor::encode_list(&ids)?;
            overrides.trust_anchor_ids = Some(ids);
            return Ok((self.clone(), overrides));
        }
        let mut profile = self.profile().clone();
        crate::trust_anchor::replace_profile_ids(&mut profile, &ids)?;
        overrides.trust_anchor_ids = None;
        Ok((self.clone().with_profile(profile), overrides))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CompileError {
    #[error("invalid TLS configuration: {0}")]
    Invalid(String),
    #[error("TLS configuration has unsupported or prohibited capabilities: {0:?}")]
    Capabilities(Vec<CapabilityIssue>),
}

impl From<CompileError> for TlsError {
    fn from(error: CompileError) -> Self {
        Self::InvalidProfile(error.to_string())
    }
}

/// Shared, immutable inputs. Randomness, secrets and tickets live in drivers.
#[derive(Debug)]
pub struct CompiledClientConfig {
    pub(crate) profile: Arc<TlsProfile>,
    pub(crate) hello_profile: Arc<TlsProfile>,
    pub(crate) transport: Transport,
    pub(crate) options: CompileOptions,
    decoded: BTreeMap<String, Arc<[u8]>>,
    pub(crate) encoding: Arc<encoding::EncodingPlan>,
    metadata: metadata::ExtensionMetadata,
    issues: Vec<CapabilityIssue>,
    pub(crate) trust_generation: [u8; 32],
}

impl CompiledClientConfig {
    pub fn compile(
        profile: impl Into<Arc<TlsProfile>>,
        transport: Transport,
        options: CompileOptions,
    ) -> Result<Arc<Self>, CompileError> {
        let profile = profile.into();
        let hello_profile = hello_profile(&profile, transport);
        if hello_profile.tls_min_version.as_u16() > hello_profile.tls_max_version.as_u16() {
            return Err(CompileError::Invalid(
                "minimum TLS version exceeds maximum".into(),
            ));
        }
        ClientHelloBuilder::new(&hello_profile, "")
            .validate_static_profile()
            .map_err(|error| CompileError::Invalid(error.to_string()))?;
        let mut decoded = BTreeMap::new();
        for extension in &hello_profile.extensions {
            let values: &[String] = match &extension.source {
                ExtensionSource::RawBytes { data } => std::slice::from_ref(data),
                ExtensionSource::TrustAnchorIds { ids, .. } => ids,
                _ => &[],
            };
            for value in values {
                let bytes =
                    decode_hex(value).map_err(|error| CompileError::Invalid(error.to_string()))?;
                if bytes.len() > u16::MAX as usize {
                    return Err(CompileError::Invalid(
                        "extension payload exceeds 65535 bytes".into(),
                    ));
                }
                if matches!(extension.source, ExtensionSource::TrustAnchorIds { .. })
                    && (bytes.is_empty() || bytes.len() > 255)
                {
                    return Err(CompileError::Invalid(
                        "trust anchor id must contain 1..=255 bytes".into(),
                    ));
                }
                decoded.insert(value.clone(), Arc::from(bytes));
            }
        }
        let issues = capability_issues(&hello_profile, transport, &options, &decoded)?;
        if issues
            .iter()
            .any(|issue| issue.reason == CapabilityReason::ProhibitedByPolicy)
            || (options.admission == Admission::Complete && !issues.is_empty())
        {
            return Err(CompileError::Capabilities(issues));
        }
        let trust_generation = crate::session_store::client::trust_generation(
            options.custom_ca_anchors.as_deref().map(Vec::as_slice),
        );
        let encoding = Arc::new(encoding::EncodingPlan::compile(&hello_profile, &decoded)?);
        let metadata = metadata::ExtensionMetadata::compile(&hello_profile, &decoded);
        Ok(Arc::new(Self {
            profile,
            hello_profile,
            transport,
            options,
            decoded,
            encoding,
            metadata,
            issues,
            trust_generation,
        }))
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.profile
    }
    pub fn transport(&self) -> Transport {
        self.transport
    }
    pub fn capability_issues(&self) -> &[CapabilityIssue] {
        &self.issues
    }

    pub(crate) fn decoded(&self, value: &str) -> Option<&[u8]> {
        self.decoded.get(value).map(AsRef::as_ref)
    }

    pub(crate) fn offers_alps(&self, protocol: &[u8]) -> bool {
        self.metadata.offers_alps(protocol)
    }

    /// Membership in the actual first ALPN offer, including opaque raw names.
    pub(crate) fn offers_alpn(&self, protocol: &[u8], overlay: Option<&ConnectionOverlay>) -> bool {
        if let Some(overlay) = overlay {
            return overlay.offers_alpn(protocol);
        }
        self.metadata
            .alpn_offer
            .as_ref()
            .is_ok_and(|names| names.iter().any(|name| name == protocol))
    }

    #[cfg(test)]
    pub(crate) fn validate_connection(&self, inputs: &ConnectionInputs) -> Result<(), TlsError> {
        let overlay = self.resolve_overlay(inputs)?;
        self.validate_connection_with_overlay(inputs, overlay.as_deref())
    }

    pub(crate) fn resolve_overlay(
        &self,
        inputs: &ConnectionInputs,
    ) -> Result<Option<Arc<ConnectionOverlay>>, TlsError> {
        let values = &inputs.hello_overrides;
        if values.alpn_protocols.is_none()
            && values.alps_protocols.is_none()
            && values.trust_anchor_ids.is_none()
        {
            return Ok(None);
        }
        self.connection_overlay(values).map(Some)
    }

    pub(crate) fn validate_connection_with_overlay(
        &self,
        inputs: &ConnectionInputs,
        overlay: Option<&ConnectionOverlay>,
    ) -> Result<(), TlsError> {
        let Some(required) = inputs.required_alpn.as_ref() else {
            return Ok(());
        };
        let protocols_match = match overlay {
            Some(overlay) => overlay
                .alpn()?
                .iter()
                .map(Vec::as_slice)
                .eq(required.iter().map(|name| name.as_bytes())),
            None => required == &self.profile.alpn_protocols,
        };
        if !protocols_match {
            return Err(TlsError::InvalidProfile(
                "ALPN profile conflicts with connection protocols".into(),
            ));
        }
        if !required.is_empty()
            && !self
                .metadata
                .protocols(ext_type::ALPN)
                .iter()
                .any(|entry| entry.source != metadata::ProtocolSource::Unsupported)
        {
            return Err(TlsError::InvalidProfile(
                "required ALPN extension is absent".into(),
            ));
        }
        // A raw payload cannot be rewritten by an H1/H3 ALPN overlay. Check
        // before consuming tickets or generating any connection secrets.
        for code in [
            ext_type::ALPN,
            ext_type::APPLICATION_SETTINGS,
            ext_type::APPLICATION_SETTINGS_NEW,
        ] {
            for entry in self
                .metadata
                .protocols(code)
                .iter()
                .filter(|entry| entry.source == metadata::ProtocolSource::Raw)
            {
                let protocols = entry.bytes.as_ref().map_err(|_| {
                    TlsError::InvalidProfile(
                        if code == ext_type::ALPN {
                            "invalid raw ALPN payload"
                        } else {
                            "invalid raw ALPS payload"
                        }
                        .into(),
                    )
                })?;
                let compatible = if code == ext_type::ALPN {
                    protocols
                        .iter()
                        .map(Vec::as_slice)
                        .eq(required.iter().map(|p| p.as_bytes()))
                } else {
                    protocols
                        .iter()
                        .all(|p| required.iter().any(|a| a.as_bytes() == p))
                };
                if !compatible {
                    return Err(TlsError::InvalidProfile(
                        if code == ext_type::ALPN {
                            "raw ALPN conflicts with connection protocols"
                        } else {
                            "raw ALPS conflicts with connection protocols"
                        }
                        .into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn hello_profile(profile: &Arc<TlsProfile>, transport: Transport) -> Arc<TlsProfile> {
    if transport == Transport::Tcp {
        return profile.clone();
    }
    let mut hello = (**profile).clone();
    hello.tls_min_version = TlsVersion::Tls13;
    hello.tls_max_version = TlsVersion::Tls13;
    hello.session_id_length = 0;
    if !hello
        .extensions
        .iter()
        .any(|ext| ext.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS)
    {
        let index = hello
            .extensions
            .iter()
            .position(|ext| {
                matches!(
                    ext.extension_type,
                    ext_type::PADDING | ext_type::PRE_SHARED_KEY
                )
            })
            .unwrap_or(hello.extensions.len());
        hello.extensions.insert(
            index,
            ExtensionSpec {
                extension_type: ext_type::QUIC_TRANSPORT_PARAMETERS,
                source: ExtensionSource::Auto,
            },
        );
    }
    Arc::new(hello)
}
