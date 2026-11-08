//! TLS Trust Anchor Identifiers (draft-ietf-tls-trust-anchor-ids-06).

use std::sync::{Arc, Mutex};

use rustls_pki_types::TrustAnchor;
use serde::{Deserialize, Serialize};

use crate::error::{AlertDescription, Result, TlsError};
use crate::profile::types::{ExtensionSource, TlsProfile};

pub const EXTENSION_TYPE: u16 = 0xca34;

/// A checked binary RELATIVE-OID, excluding ASN.1 tag/length and TLS length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustAnchorId(Vec<u8>);

impl TrustAnchorId {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 32 {
            return Err(invalid("trust anchor ID must contain 1..32 bytes"));
        }
        let mut start = true;
        for &byte in &bytes {
            if start && byte == 0x80 {
                return Err(invalid("non-minimal trust anchor RELATIVE-OID"));
            }
            start = byte & 0x80 == 0;
        }
        if !start {
            return Err(invalid("unterminated trust anchor RELATIVE-OID"));
        }
        Ok(Self(bytes))
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 64
            || !value.len().is_multiple_of(2)
            || !value.is_ascii()
        {
            return Err(invalid("invalid trust anchor ID hex"));
        }
        let bytes = value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16);
                let lo = (pair[1] as char).to_digit(16);
                hi.zip(lo)
                    .map(|(hi, lo)| ((hi << 4) | lo) as u8)
                    .ok_or_else(|| invalid("invalid trust anchor ID hex"))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::new(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl<'de> Deserialize<'de> for TrustAnchorId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Serialize for TrustAnchorId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

fn invalid(message: &str) -> TlsError {
    TlsError::local_alert(AlertDescription::DecodeError, message)
}

pub fn decode_list(payload: &[u8], allow_empty: bool) -> Result<Vec<TrustAnchorId>> {
    if payload.len() < 2
        || usize::from(u16::from_be_bytes([payload[0], payload[1]])) != payload.len() - 2
    {
        return Err(invalid("trust anchor list length mismatch"));
    }
    if !allow_empty && payload.len() == 2 {
        return Err(invalid("server trust anchor list must not be empty"));
    }
    let mut ids = Vec::new();
    let mut remaining = &payload[2..];
    while let Some((&len, tail)) = remaining.split_first() {
        let len = usize::from(len);
        if tail.len() < len {
            return Err(invalid("truncated trust anchor ID"));
        }
        ids.push(TrustAnchorId::new(tail[..len].to_vec())?);
        remaining = &tail[len..];
    }
    Ok(ids)
}

pub fn encode_list(ids: &[TrustAnchorId]) -> Result<Vec<u8>> {
    let len = ids.iter().map(|id| 1 + id.0.len()).sum::<usize>();
    if len > usize::from(u16::MAX) - 2 {
        return Err(TlsError::InvalidProfile(
            "trust anchor list exceeds TLS extension size".into(),
        ));
    }
    let mut out = Vec::with_capacity(len + 2);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    for id in ids {
        out.push(id.0.len() as u8);
        out.extend_from_slice(&id.0);
    }
    Ok(out)
}

/// Stable identity of all trust-anchor fields, including local constraints.
pub fn anchor_identity(anchor: &TrustAnchor<'_>) -> String {
    use aws_lc_rs::digest::{Context, SHA256};
    let mut hash = Context::new(&SHA256);
    hash.update(b"lkrequest trust anchor v1\0");
    for part in [
        Some(anchor.subject.as_ref()),
        Some(anchor.subject_public_key_info.as_ref()),
        anchor.name_constraints.as_ref().map(|nc| nc.as_ref()),
    ] {
        hash.update(&[u8::from(part.is_some())]);
        let bytes = part.unwrap_or_default();
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hex(hash.finish().as_ref())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorBinding {
    pub anchor_identity: String,
    pub id: TrustAnchorId,
}

#[derive(Debug, Clone, Default)]
pub struct TrustAnchorCatalog {
    bindings: Vec<TrustAnchorBinding>,
}

impl TrustAnchorCatalog {
    pub fn new(
        mut bindings: Vec<TrustAnchorBinding>,
        custom: &[TrustAnchor<'static>],
    ) -> Result<Self> {
        let roots: std::collections::HashSet<_> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .chain(custom)
            .map(anchor_identity)
            .collect();
        for binding in &bindings {
            if !roots.contains(&binding.anchor_identity) {
                return Err(TlsError::InvalidProfile(
                    "trust anchor ID binding refers to an untrusted root".into(),
                ));
            }
        }
        #[derive(Deserialize)]
        struct Data {
            entries: Vec<Entry>,
        }
        #[derive(Deserialize)]
        struct Entry {
            anchor_identity: Option<String>,
            id: TrustAnchorId,
        }
        static BUILTIN: std::sync::OnceLock<Vec<TrustAnchorBinding>> = std::sync::OnceLock::new();
        let builtin = BUILTIN.get_or_init(|| {
            let data: Data = serde_json::from_str(include_str!("../data/trust_anchor_ids.json"))
                .expect("checked bundled TAI metadata");
            data.entries
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .anchor_identity
                        .map(|anchor_identity| TrustAnchorBinding {
                            anchor_identity,
                            id: entry.id,
                        })
                })
                .collect()
        });
        bindings.extend(
            builtin
                .iter()
                .filter(|binding| roots.contains(&binding.anchor_identity))
                .cloned(),
        );
        let mut unique = std::collections::HashMap::new();
        for binding in &bindings {
            if unique
                .insert(&binding.id, &binding.anchor_identity)
                .is_some_and(|existing| existing != &binding.anchor_identity)
            {
                return Err(TlsError::InvalidProfile(
                    "conflicting trust anchor ID bindings".into(),
                ));
            }
        }
        Ok(Self { bindings })
    }
    pub fn ids(&self) -> Vec<TrustAnchorId> {
        let mut ids: Vec<_> = self.bindings.iter().map(|b| b.id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }
    pub fn ids_for_anchor(&self, identity: &str) -> Vec<TrustAnchorId> {
        self.bindings
            .iter()
            .filter(|b| b.anchor_identity == identity)
            .map(|b| b.id.clone())
            .collect()
    }
    pub fn select(&self, info: &TrustAnchorInfo) -> Option<TrustAnchorId> {
        let usable: std::collections::HashSet<_> = self.bindings.iter().map(|b| &b.id).collect();
        info.available_ids
            .iter()
            .find(|id| usable.contains(id) && info.requested_ids.as_slice() != [(*id).clone()])
            .cloned()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorAdvertisement {
    #[default]
    Profile,
    Trusted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorRecovery {
    #[default]
    Disabled,
    Once,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustAnchorPolicy {
    pub advertisement: TrustAnchorAdvertisement,
    pub recovery: TrustAnchorRecovery,
}

pub fn replace_profile_ids(profile: &mut TlsProfile, ids: &[TrustAnchorId]) -> Result<()> {
    let spec = profile
        .extensions
        .iter_mut()
        .find(|ext| ext.extension_type == EXTENSION_TYPE)
        .ok_or_else(|| {
            TlsError::InvalidProfile("TAI policy requires a trust_anchors extension slot".into())
        })?;
    let _ = encode_list(ids)?;
    spec.source = ExtensionSource::TrustAnchorIds {
        ids: ids.iter().map(TrustAnchorId::to_hex).collect(),
        shuffle: false,
    };
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustAnchorInfo {
    pub requested_ids: Vec<TrustAnchorId>,
    /// Peer hints, not a trust decision; unauthenticated until `authenticated`.
    pub available_ids: Vec<TrustAnchorId>,
    pub matched_request: bool,
    pub verified_anchor: Option<String>,
    /// Strict validation and server Finished succeeded for this attempt.
    pub authenticated: bool,
    pub ech_rejected: bool,
    pub recovered: bool,
    pub failure: Option<String>,
    pub recovery_eligible: bool,
    pub previous_attempt: Option<Box<TrustAnchorInfo>>,
}

/// Allocate one observer per connection attempt; clones observe that attempt only.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchorObserver(Arc<Mutex<TrustAnchorInfo>>);

impl TrustAnchorObserver {
    pub fn snapshot(&self) -> TrustAnchorInfo {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn update(&self, update: impl FnOnce(&mut TrustAnchorInfo)) {
        update(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()));
    }
    pub fn record_error(&self, error: &TlsError) {
        self.update(|info| {
            info.failure = Some(error.to_string());
            info.recovery_eligible = !info.authenticated
                && !info.ech_rejected
                && !info.available_ids.is_empty()
                && match error {
                    TlsError::UnknownIssuer(_) => true,
                    TlsError::Io(e) => matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ),
                    TlsError::Alert(alert) => matches!(
                        alert.description,
                        AlertDescription::HandshakeFailure | AlertDescription::UnknownCa
                    ),
                    _ => false,
                };
        });
    }
}

/// Keeps ordinary PSK resumption while suppressing early application data.
#[derive(Debug)]
pub struct WithoutEarlyData(pub Arc<dyn crate::session_store::SessionStore>);

impl crate::session_store::SessionStore for WithoutEarlyData {
    fn store(&self, host: &str, ticket: crate::session_store::SessionTicketData) {
        self.0.store(host, ticket);
    }
    fn take(&self, host: &str) -> Option<crate::session_store::SessionTicketData> {
        self.0.take(host).map(|mut ticket| {
            ticket.max_early_data_size = 0;
            ticket
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_limits_oid_validation_and_order() {
        for bytes in [vec![], vec![0x80, 0], vec![0x81], vec![1; 33]] {
            assert!(TrustAnchorId::new(bytes).is_err());
        }
        let ids = ["d6790904", "82df130201"].map(|id| TrustAnchorId::from_hex(id).unwrap());
        assert_eq!(
            decode_list(&encode_list(&ids).unwrap(), false).unwrap(),
            ids
        );
        assert!(decode_list(&[0, 0], false).is_err());
        assert!(decode_list(&[0, 2, 2, 1], false).is_err());
        assert!(encode_list(&vec![ids[0].clone(); 14000]).is_err());
        assert!(decode_list(&[0, 0], true).unwrap().is_empty());
        let mut large_component = vec![0xff; 31];
        large_component.push(0x7f);
        assert!(TrustAnchorId::new(large_component).is_ok());
    }
    #[test]
    fn metadata_does_not_grant_trust() {
        let binding = TrustAnchorBinding {
            anchor_identity: "unknown".into(),
            id: TrustAnchorId::new(vec![1]).unwrap(),
        };
        assert!(TrustAnchorCatalog::new(vec![binding], &[]).is_err());
        let mut root = webpki_roots::TLS_SERVER_ROOTS[0].clone();
        let original = anchor_identity(&root);
        root.name_constraints = Some(vec![1, 2, 3].into());
        assert_ne!(original, anchor_identity(&root));
        let id = TrustAnchorId::from_hex("81fd5901").unwrap();
        let conflicting = webpki_roots::TLS_SERVER_ROOTS[..2]
            .iter()
            .map(|root| TrustAnchorBinding {
                anchor_identity: anchor_identity(root),
                id: id.clone(),
            })
            .collect();
        assert!(TrustAnchorCatalog::new(conflicting, &[]).is_err());
    }

    #[test]
    fn only_bound_roots_are_usable_in_server_preference_order() {
        let catalog = TrustAnchorCatalog::new(Vec::new(), &[]).unwrap();
        let ids = catalog.ids();
        assert!(!ids.is_empty() && ids.len() <= 13);
        let unknown = TrustAnchorId::from_hex("81fd5901").unwrap();
        let mut info = TrustAnchorInfo {
            available_ids: vec![unknown, ids[1].clone(), ids[0].clone()],
            ..Default::default()
        };
        assert_eq!(catalog.select(&info), Some(ids[1].clone()));
        info.requested_ids = vec![ids[1].clone()];
        assert_eq!(catalog.select(&info), Some(ids[0].clone()));
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../data/trust_anchor_ids.json")).unwrap();
        for entry in data["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["kind"] == "additional_certs")
        {
            let id = TrustAnchorId::from_hex(entry["id"].as_str().unwrap()).unwrap();
            assert!(
                !ids.contains(&id),
                "intermediate metadata must not add trust"
            );
        }
    }

    #[test]
    fn recovery_hints_do_not_mask_terminal_validation_errors() {
        let observer = TrustAnchorObserver::default();
        observer.update(|info| info.available_ids = vec![TrustAnchorId::new(vec![1]).unwrap()]);
        observer.record_error(&TlsError::UnknownIssuer("unknown".into()));
        assert!(observer.snapshot().recovery_eligible);
        for error in [
            TlsError::CertificateError("expired".into()),
            TlsError::CryptoError("invalid signature".into()),
            TlsError::local_alert(AlertDescription::DecodeError, "bad list"),
        ] {
            observer.record_error(&error);
            assert!(!observer.snapshot().recovery_eligible);
        }
        observer.update(|info| info.ech_rejected = true);
        observer.record_error(&TlsError::UnknownIssuer("unknown".into()));
        assert!(!observer.snapshot().recovery_eligible);
    }

    #[test]
    fn recovery_disables_early_data_but_retains_psk_resumption() {
        use crate::session_store::{
            AlpsSessionState, InMemorySessionStore, SessionStore, SessionTicketData,
            TicketTlsVersion,
        };
        let store = Arc::new(InMemorySessionStore::new());
        let ticket = SessionTicketData {
            ticket: vec![1],
            resumption_psk: vec![2; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn: Some("h3".into()),
            alps: AlpsSessionState::NotNegotiated,
            hkdf_algorithm: crate::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: crate::crypto::aead::AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: u32::MAX,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        };
        let guarded = WithoutEarlyData(store);
        guarded.store("localhost", ticket);
        let taken = guarded.take("localhost").unwrap();
        assert_eq!(taken.max_early_data_size, 0);
        assert_eq!(taken.resumption_psk, vec![2; 32]);
        assert_eq!(taken.ticket, vec![1]);
    }
}
