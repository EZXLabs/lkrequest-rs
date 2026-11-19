//! HSTS / scheme-upgrade policy.
//!
//! Controls whether an `http://` URL (initial request or redirect target) is
//! upgraded to `https://` before connecting — the customizable equivalent of a
//! browser's HSTS handling (RFC 6797).
//!
//! Because lkrequest emulates a browser's *network* layer, it ships no dynamic
//! HSTS store and no compiled preload list by default: a fresh session is
//! stateless ("first visit"), so the default [`NoHsts`] performs no upgrades —
//! matching a browser that has never seen the host and has no preload entry.
//! Callers that need HSTS — to mirror Chrome's fully-preloaded gTLDs, to replay
//! a session that already learned HSTS, or to enforce their own rules — plug a
//! policy in via
//! [`SessionBuilder::hsts_policy`](crate::session::SessionBuilder::hsts_policy).

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Decides whether a host must be treated as HTTPS-only.
///
/// When [`should_upgrade`](HstsPolicy::should_upgrade) returns `true` for a
/// host, an `http://` URL for that host (initial request or redirect target) is
/// rewritten to `https://` — and an explicit `:80` to `:443`, per RFC 6797
/// §8.3 — before the connection is made, exactly as a browser does for an HSTS
/// or preloaded host.
///
/// A plain closure `Fn(&str) -> bool` implements this trait, so simple rules can
/// be passed inline:
///
/// ```
/// # use lkrequest::Client;
/// # let client = Client::builder().build();
/// let session = client
///     .session()
///     .hsts_policy(|host: &str| host.ends_with(".internal"))
///     .build();
/// ```
pub trait HstsPolicy: Send + Sync {
    /// Whether `host` must be upgraded from `http` to `https` before connecting.
    fn should_upgrade(&self, host: &str) -> bool;

    /// Record a `Strict-Transport-Security` response header observed for `host`.
    ///
    /// Stateless policies ignore this (the default). Stateful policies such as
    /// [`DynamicHsts`] use it to learn HSTS hosts at runtime, matching a
    /// long-lived browser session that accumulates HSTS state.
    fn record_sts(&self, host: &str, sts_header: &str) {
        let _ = (host, sts_header);
    }
}

impl<F> HstsPolicy for F
where
    F: Fn(&str) -> bool + Send + Sync,
{
    fn should_upgrade(&self, host: &str) -> bool {
        (self)(host)
    }
}

/// Default policy: never upgrade.
///
/// A fresh session is a stateless "first visit" with no HSTS history, so nothing
/// is upgraded — matching a browser that has never seen the host and carries no
/// preload entry for it.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHsts;

impl HstsPolicy for NoHsts {
    fn should_upgrade(&self, _host: &str) -> bool {
        false
    }
}

/// A representative subset of the gTLDs Chrome ships as HSTS-preloaded in their
/// entirety (every host under them is HTTPS-only). Enabled via
/// [`StaticHsts::with_preloaded_tlds`]. Not exhaustive — Chrome's list is larger
/// and changes over time; callers needing exactness should supply their own.
const FULLY_PRELOADED_TLDS: &[&str] = &[
    "dev", "app", "page", "foo", "dad", "prof", "esq", "new", "boo", "rsvp", "channel", "gle",
];

/// Upgrade a fixed set of hosts (and, optionally, whole preloaded gTLDs).
///
/// Host matching is suffix-aware: listing `example.com` also upgrades
/// `api.example.com`, matching HSTS's `includeSubDomains` semantics.
#[derive(Debug, Default, Clone)]
pub struct StaticHsts {
    hosts: Vec<String>,
    preloaded_tlds: bool,
}

impl StaticHsts {
    /// Build from an explicit list of HSTS hosts.
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            hosts: hosts
                .into_iter()
                .map(|h| normalize_host(&h.into()))
                .collect(),
            preloaded_tlds: false,
        }
    }

    /// Also upgrade every host under a gTLD that Chrome preloads in full
    /// (`.dev`, `.app`, …; see `FULLY_PRELOADED_TLDS`). Off by default.
    pub fn with_preloaded_tlds(mut self) -> Self {
        self.preloaded_tlds = true;
        self
    }
}

impl HstsPolicy for StaticHsts {
    fn should_upgrade(&self, host: &str) -> bool {
        let host = normalize_host(host);
        if self.hosts.iter().any(|h| host_matches(&host, h)) {
            return true;
        }
        if self.preloaded_tlds {
            if let Some(tld) = host.rsplit('.').next() {
                return FULLY_PRELOADED_TLDS.contains(&tld);
            }
        }
        false
    }
}

/// Stateful policy that learns HSTS hosts from `Strict-Transport-Security`
/// response headers within the session, mirroring a browser's dynamic HSTS
/// store. Entries expire after `max-age`; subdomains are covered only when
/// `includeSubDomains` was received.
#[derive(Debug, Default)]
pub struct DynamicHsts {
    hosts: RwLock<HashMap<String, HstsEntry>>,
}

#[derive(Debug)]
struct HstsEntry {
    expires: Option<Instant>,
    include_subdomains: bool,
}

impl DynamicHsts {
    /// Create an empty dynamic store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed the store with known HSTS hosts — e.g. replaying the learned
    /// state of a prior browser session. Seeds do not expire and include
    /// subdomains until replaced or removed by a valid response header.
    pub fn with_seed<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set = hosts
            .into_iter()
            .map(|h| {
                (
                    normalize_host(&h.into()),
                    HstsEntry {
                        expires: None,
                        include_subdomains: true,
                    },
                )
            })
            .collect();
        Self {
            hosts: RwLock::new(set),
        }
    }
}

impl HstsPolicy for DynamicHsts {
    fn should_upgrade(&self, host: &str) -> bool {
        let host = normalize_host(host);
        let now = Instant::now();
        let entries = self.hosts.read();
        let mut suffix = host.as_str();
        loop {
            if entries.get(suffix).is_some_and(|entry| {
                entry.expires.is_none_or(|expires| now < expires)
                    && (suffix.len() == host.len() || entry.include_subdomains)
            }) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => return false,
            }
        }
    }

    fn record_sts(&self, host: &str, sts_header: &str) {
        let host = normalize_host(host);
        if host.is_empty() || crate::dns::literal_ip(&host).is_some() {
            return;
        }
        let Some((max_age, include_subdomains)) = parse_sts(sts_header) else {
            return;
        };
        let now = Instant::now();
        let Some(expires) = now.checked_add(Duration::from_secs(max_age)) else {
            return;
        };
        let mut hosts = self.hosts.write();
        hosts.retain(|_, entry| entry.expires.is_none_or(|expires| now < expires));
        if max_age == 0 {
            hosts.remove(&host);
        } else {
            hosts.insert(
                host,
                HstsEntry {
                    expires: Some(expires),
                    include_subdomains,
                },
            );
        }
    }
}

/// Normalize a host for comparison: lowercase and strip a trailing root dot.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// `host` equals `entry`, or is a subdomain of it (`includeSubDomains`).
fn host_matches(host: &str, entry: &str) -> bool {
    host == entry
        || host
            .strip_suffix(entry)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Parse the `max-age` directive from a `Strict-Transport-Security` header
/// value. Returns `None` if it is absent or unparseable.
fn parse_sts(header: &str) -> Option<(u64, bool)> {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut seen = HashSet::new();
    for directive in header.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(n, v)| (n.trim(), Some(v.trim())));
        if !seen.insert(name.to_ascii_lowercase()) {
            return None;
        }
        if name.eq_ignore_ascii_case("max-age") {
            let value = value?;
            let value = if let Some(quoted) = value.strip_prefix('"') {
                quoted.strip_suffix('"')?
            } else {
                value
            };
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            max_age = Some(value.parse().ok()?);
        } else if name.eq_ignore_ascii_case("includeSubDomains") {
            if value.is_some() {
                return None;
            }
            include_subdomains = true;
        }
    }
    Some((max_age?, include_subdomains))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hsts_never_upgrades() {
        assert!(!NoHsts.should_upgrade("github.com"));
        assert!(!NoHsts.should_upgrade("example.dev"));
    }

    #[test]
    fn static_hsts_exact_and_subdomain() {
        let p = StaticHsts::new(["github.com", "Example.COM"]);
        assert!(p.should_upgrade("github.com"));
        assert!(p.should_upgrade("api.github.com")); // includeSubDomains
        assert!(p.should_upgrade("example.com")); // case-insensitive entry
        assert!(p.should_upgrade("EXAMPLE.com")); // case-insensitive query
        assert!(p.should_upgrade("github.com.")); // trailing root dot
        assert!(!p.should_upgrade("notgithub.com")); // suffix without dot boundary
        assert!(!p.should_upgrade("github.com.evil.com"));
        assert!(!p.should_upgrade("other.org"));
    }

    #[test]
    fn static_hsts_preloaded_tlds_opt_in() {
        let off = StaticHsts::new(["a.com"]);
        assert!(!off.should_upgrade("anything.dev"));

        let on = StaticHsts::new(["a.com"]).with_preloaded_tlds();
        assert!(on.should_upgrade("anything.dev"));
        assert!(on.should_upgrade("deep.sub.app"));
        assert!(!on.should_upgrade("anything.com")); // .com is not fully preloaded
    }

    #[test]
    fn dynamic_hsts_records_and_clears() {
        let p = DynamicHsts::new();
        assert!(!p.should_upgrade("a.com"));

        // max-age > 0 with includeSubDomains → learn the host.
        p.record_sts("a.com", "max-age=31536000; includeSubDomains");
        assert!(p.should_upgrade("a.com"));
        assert!(p.should_upgrade("sub.a.com"));

        // max-age = 0 → forget it.
        p.record_sts("a.com", "max-age=0");
        assert!(!p.should_upgrade("a.com"));

        // Malformed header → ignored (no panic, no state change).
        p.record_sts("b.com", "includeSubDomains");
        assert!(!p.should_upgrade("b.com"));
        p.record_sts("b.com", "max-age=\"600\""); // quoted value accepted
        assert!(p.should_upgrade("b.com"));
    }

    #[test]
    fn dynamic_hsts_seed() {
        let p = DynamicHsts::with_seed(["seeded.com"]);
        assert!(p.should_upgrade("x.seeded.com"));
    }

    #[test]
    fn closure_implements_policy() {
        let p = |host: &str| host.ends_with(".internal");
        assert!(p.should_upgrade("svc.internal"));
        assert!(!p.should_upgrade("svc.example.com"));
    }

    #[test]
    fn parse_max_age_cases() {
        let parse_max_age = |header: &str| parse_sts(header).map(|(age, _)| age);
        assert_eq!(parse_max_age("max-age=600"), Some(600));
        assert_eq!(parse_max_age("max-age=0"), Some(0));
        assert_eq!(
            parse_max_age("includeSubDomains; max-age=31536000; preload"),
            Some(31_536_000)
        );
        assert_eq!(parse_max_age("MAX-AGE=42"), Some(42));
        assert_eq!(parse_max_age("max-age=\"42\""), Some(42));
        assert_eq!(parse_max_age("includeSubDomains"), None);
        assert_eq!(parse_max_age("max-age=abc"), None);
        assert_eq!(parse_max_age("max-age=1; max-age=2"), None);
        assert_eq!(parse_max_age("max-age=\"42"), None);
        assert_eq!(parse_max_age("max-age=+42"), None);
        assert_eq!(parse_max_age("max-age=42; includeSubDomains=1"), None);
    }

    #[test]
    fn dynamic_scope_expiry_and_parent_policy_are_independent() {
        let p = DynamicHsts::new();
        p.record_sts("example.com", "max-age=600");
        assert!(p.should_upgrade("example.com"));
        assert!(!p.should_upgrade("a.example.com"));
        p.record_sts("example.com", "max-age=600; includeSubDomains");
        p.record_sts("a.example.com", "max-age=0");
        assert!(p.should_upgrade("a.example.com"));
        p.hosts.write().get_mut("example.com").unwrap().expires = Some(Instant::now());
        assert!(!p.should_upgrade("example.com"));
        assert!(!p.should_upgrade("a.example.com"));
        p.record_sts("127.0.0.1", "max-age=600");
        assert!(!p.should_upgrade("127.0.0.1"));
    }
}
