//! TLS session-cache partitioning policies.

use std::sync::Arc;

use lktls::session_store::{SessionStore, SessionTicketData};

/// Controls whether TLS 1.3 session tickets are cached and offered as PSKs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsSessionResumptionPolicy {
    /// Browser-oriented default: keep two tickets per server and consume the
    /// most recently received ticket first.
    #[default]
    BrowserDefault,
    /// Never store or offer session tickets. Every connection performs a full
    /// handshake.
    Disabled,
    /// Enable resumption with an explicit per-server ticket capacity.
    Enabled { max_tickets_per_server: usize },
}

impl TlsSessionResumptionPolicy {
    pub(crate) fn create_store(self) -> Arc<dyn SessionStore> {
        match self {
            Self::BrowserDefault => Arc::new(lktls::session_store::InMemorySessionStore::new()),
            Self::Disabled => Arc::new(DisabledSessionStore),
            Self::Enabled {
                max_tickets_per_server,
            } => {
                assert!(
                    max_tickets_per_server > 0,
                    "max_tickets_per_server must be greater than zero"
                );
                Arc::new(
                    lktls::session_store::InMemorySessionStore::with_max_tickets(
                        max_tickets_per_server,
                    ),
                )
            }
        }
    }
}

#[derive(Debug)]
struct DisabledSessionStore;

impl SessionStore for DisabledSessionStore {
    fn store(&self, _host: &str, _ticket: SessionTicketData) {}

    fn take(&self, _host: &str) -> Option<SessionTicketData> {
        None
    }
}

/// Browser-style policy used to partition TLS and QUIC session tickets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsSessionCachePartitionPolicy {
    /// Preserve traditional HTTP-client behaviour: cache by server only.
    #[default]
    Unpartitioned,
    /// Partition by the top-level schemeful site.
    TopLevelSite,
    /// Partition by both top-level and frame schemeful sites.
    TopLevelAndFrameSite,
    /// Chromium's 2.5-key model: top-level site plus same/cross-site bit.
    Chromium,
    /// Firefox-style top-level partition plus OriginAttributes scope.
    Firefox,
}

/// Browsing context used to derive a TLS session-cache partition.
///
/// Site strings must be canonical schemeful sites such as
/// `https://example.com`, not arbitrary document URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPartitionContext {
    top_level_site: String,
    frame_site: String,
    nonce: Option<String>,
    browser_context: Option<String>,
}

impl NetworkPartitionContext {
    /// Create a context from top-level and frame schemeful sites.
    pub fn new(top_level_site: impl Into<String>, frame_site: impl Into<String>) -> Self {
        Self {
            top_level_site: top_level_site.into(),
            frame_site: frame_site.into(),
            nonce: None,
            browser_context: None,
        }
    }

    /// Attach a transient partition nonce for ephemeral contexts.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Attach an opaque browser context such as Firefox OriginAttributes.
    pub fn browser_context(mut self, context: impl Into<String>) -> Self {
        self.browser_context = Some(context.into());
        self
    }

    fn partition_key(&self, policy: TlsSessionCachePartitionPolicy) -> Option<String> {
        let mut parts = Vec::new();
        match policy {
            TlsSessionCachePartitionPolicy::Unpartitioned => return None,
            TlsSessionCachePartitionPolicy::TopLevelSite => {
                push_part(&mut parts, "top", &self.top_level_site);
            }
            TlsSessionCachePartitionPolicy::TopLevelAndFrameSite => {
                push_part(&mut parts, "top", &self.top_level_site);
                push_part(&mut parts, "frame", &self.frame_site);
            }
            TlsSessionCachePartitionPolicy::Chromium => {
                push_part(&mut parts, "top", &self.top_level_site);
                let cross_site = if self.top_level_site == self.frame_site {
                    "0"
                } else {
                    "1"
                };
                push_part(&mut parts, "cross", cross_site);
            }
            TlsSessionCachePartitionPolicy::Firefox => {
                push_part(&mut parts, "top", &self.top_level_site);
            }
        }
        if let Some(nonce) = self.nonce.as_deref() {
            push_part(&mut parts, "nonce", nonce);
        }
        if let Some(context) = self.browser_context.as_deref() {
            push_part(&mut parts, "context", context);
        }
        Some(parts.concat())
    }
}

fn push_part(output: &mut Vec<String>, label: &str, value: &str) {
    output.push(format!("{label}:{}:{value};", value.len()));
}

#[derive(Debug)]
pub(crate) struct PartitionedSessionStore {
    inner: Arc<dyn SessionStore>,
    partition: String,
}

impl PartitionedSessionStore {
    pub(crate) fn wrap(
        inner: Arc<dyn SessionStore>,
        policy: TlsSessionCachePartitionPolicy,
        context: Option<&NetworkPartitionContext>,
    ) -> Arc<dyn SessionStore> {
        let Some(partition) = context.and_then(|context| context.partition_key(policy)) else {
            return inner;
        };
        Arc::new(Self { inner, partition })
    }

    fn store_key(&self, server: &str) -> String {
        format!(
            "partition:{}:{}server:{}:{}",
            self.partition.len(),
            self.partition,
            server.len(),
            server
        )
    }
}

impl SessionStore for PartitionedSessionStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
        self.inner.store(&self.store_key(host), ticket);
    }

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        self.inner.take(&self.store_key(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lktls::crypto::aead::AeadAlgorithm;
    use lktls::crypto::hkdf::HkdfAlgorithm;
    use lktls::session_store::{InMemorySessionStore, TicketTlsVersion};
    use std::time::Instant;

    fn ticket(marker: u8) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![marker],
            resumption_psk: vec![marker; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
            used_extended_master_secret: None,
        }
    }

    #[test]
    fn chromium_uses_top_level_site_and_cross_site_bit() {
        let same_site = NetworkPartitionContext::new("https://example.com", "https://example.com");
        let cross_site_a =
            NetworkPartitionContext::new("https://example.com", "https://cdn-a.test");
        let cross_site_b =
            NetworkPartitionContext::new("https://example.com", "https://cdn-b.test");

        assert_ne!(
            same_site.partition_key(TlsSessionCachePartitionPolicy::Chromium),
            cross_site_a.partition_key(TlsSessionCachePartitionPolicy::Chromium)
        );
        assert_eq!(
            cross_site_a.partition_key(TlsSessionCachePartitionPolicy::Chromium),
            cross_site_b.partition_key(TlsSessionCachePartitionPolicy::Chromium)
        );
    }

    #[test]
    fn double_keyed_policy_distinguishes_frame_sites() {
        let first = NetworkPartitionContext::new("https://example.com", "https://cdn-a.test");
        let second = NetworkPartitionContext::new("https://example.com", "https://cdn-b.test");
        assert_ne!(
            first.partition_key(TlsSessionCachePartitionPolicy::TopLevelAndFrameSite),
            second.partition_key(TlsSessionCachePartitionPolicy::TopLevelAndFrameSite)
        );
    }

    #[test]
    fn browser_context_and_nonce_extend_partition() {
        let base = NetworkPartitionContext::new("https://example.com", "https://example.com");
        assert_ne!(
            base.partition_key(TlsSessionCachePartitionPolicy::Firefox),
            base.clone()
                .browser_context("privateBrowsingId=1")
                .partition_key(TlsSessionCachePartitionPolicy::Firefox)
        );
        assert_ne!(
            base.partition_key(TlsSessionCachePartitionPolicy::Chromium),
            base.nonce("opaque-nonce")
                .partition_key(TlsSessionCachePartitionPolicy::Chromium)
        );
    }

    #[test]
    fn partitioned_stores_isolate_same_server() {
        let base: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let first_context = NetworkPartitionContext::new("https://first.test", "https://cdn.test");
        let second_context =
            NetworkPartitionContext::new("https://second.test", "https://cdn.test");
        let first = PartitionedSessionStore::wrap(
            Arc::clone(&base),
            TlsSessionCachePartitionPolicy::TopLevelSite,
            Some(&first_context),
        );
        let second = PartitionedSessionStore::wrap(
            base,
            TlsSessionCachePartitionPolicy::TopLevelSite,
            Some(&second_context),
        );

        first.store("cdn.test:443", ticket(1));
        assert!(second.take("cdn.test:443").is_none());
        assert_eq!(first.take("cdn.test:443").unwrap().ticket, vec![1]);
    }

    #[test]
    fn unpartitioned_or_missing_context_returns_the_original_store() {
        let base: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let context = NetworkPartitionContext::new("https://top.test", "https://frame.test");

        let unpartitioned = PartitionedSessionStore::wrap(
            Arc::clone(&base),
            TlsSessionCachePartitionPolicy::Unpartitioned,
            Some(&context),
        );
        let without_context = PartitionedSessionStore::wrap(
            Arc::clone(&base),
            TlsSessionCachePartitionPolicy::TopLevelSite,
            None,
        );

        assert!(Arc::ptr_eq(&base, &unpartitioned));
        assert!(Arc::ptr_eq(&base, &without_context));
    }

    #[test]
    fn wrappers_with_the_same_partition_share_server_tickets() {
        let base: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let context = NetworkPartitionContext::new("https://top.test", "https://frame.test");
        let first = PartitionedSessionStore::wrap(
            Arc::clone(&base),
            TlsSessionCachePartitionPolicy::TopLevelAndFrameSite,
            Some(&context),
        );
        let second = PartitionedSessionStore::wrap(
            base,
            TlsSessionCachePartitionPolicy::TopLevelAndFrameSite,
            Some(&context),
        );

        first.store("cdn.test:443", ticket(7));

        assert_eq!(second.take("cdn.test:443").unwrap().ticket, vec![7]);
    }

    #[test]
    fn top_level_policy_ignores_frame_but_double_keyed_policy_isolates_it() {
        let first_context =
            NetworkPartitionContext::new("https://top.test", "https://frame-a.test");
        let second_context =
            NetworkPartitionContext::new("https://top.test", "https://frame-b.test");

        let top_level_base: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let top_level_first = PartitionedSessionStore::wrap(
            Arc::clone(&top_level_base),
            TlsSessionCachePartitionPolicy::TopLevelSite,
            Some(&first_context),
        );
        let top_level_second = PartitionedSessionStore::wrap(
            top_level_base,
            TlsSessionCachePartitionPolicy::TopLevelSite,
            Some(&second_context),
        );
        top_level_first.store("cdn.test:443", ticket(8));
        assert_eq!(
            top_level_second.take("cdn.test:443").unwrap().ticket,
            vec![8]
        );

        let double_keyed_base: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let double_keyed_first = PartitionedSessionStore::wrap(
            Arc::clone(&double_keyed_base),
            TlsSessionCachePartitionPolicy::TopLevelAndFrameSite,
            Some(&first_context),
        );
        let double_keyed_second = PartitionedSessionStore::wrap(
            double_keyed_base,
            TlsSessionCachePartitionPolicy::TopLevelAndFrameSite,
            Some(&second_context),
        );
        double_keyed_first.store("cdn.test:443", ticket(9));
        assert!(double_keyed_second.take("cdn.test:443").is_none());
    }

    #[test]
    fn disabled_resumption_store_never_returns_psk_tickets() {
        let store = TlsSessionResumptionPolicy::Disabled.create_store();
        store.store("example.test:443", ticket(1));
        assert!(store.take("example.test:443").is_none());
    }

    #[test]
    fn explicit_ticket_capacity_keeps_latest_ticket() {
        let store = TlsSessionResumptionPolicy::Enabled {
            max_tickets_per_server: 1,
        }
        .create_store();
        store.store("example.test:443", ticket(1));
        store.store("example.test:443", ticket(2));

        assert_eq!(store.take("example.test:443").unwrap().ticket, vec![2]);
        assert!(store.take("example.test:443").is_none());
    }
}
