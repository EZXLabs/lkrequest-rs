//! TLS handshake message construction and parsing.
//!
//! This module contains:
//! - [`client_hello`]: Byte-level ClientHello builder driven by a [`TlsProfile`](crate::profile::types::TlsProfile).
//! - [`server_hello`]: ServerHello parser (extracts version, cipher suite, key share, etc.).
//! - [`tls12`]: TLS 1.2 handshake state machine (full + abbreviated with session ticket resumption).
//! - [`tls13`]: TLS 1.3 handshake state machine (with PSK resumption and HelloRetryRequest support).
//!
//! The [`content_type`] and [`handshake_type`] sub-modules provide TLS protocol constants.

pub mod client_hello;
pub mod driver;
pub mod server_hello;
pub mod tls12;
pub mod tls13;

/// Strip the square brackets an IPv6 literal carries inside a URI authority.
///
/// `url::Url::host_str()` returns IPv6 hosts in their RFC 3986 authority form,
/// `"[::1]"`. That form is right for a `Host` header or an HTTP `:authority`,
/// but wrong everywhere TLS wants a bare host: `"[::1]".parse::<IpAddr>()`
/// fails, and so does `ServerName::try_from("[::1]")`. Callers that need to
/// decide "is this an IP?" or hand the name to a certificate verifier must
/// normalize first.
///
/// Brackets are stripped **only** when they wrap something that really is an
/// IPv6 address — RFC 3986 §3.2.2 permits them for nothing else. `"[example.com]"`
/// is therefore left intact and goes on to fail name validation, rather than
/// being quietly accepted as `example.com`. Anything else is returned unchanged,
/// so this is safe to apply unconditionally.
pub fn strip_ipv6_brackets(hostname: &str) -> &str {
    match hostname
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) if inner.parse::<std::net::Ipv6Addr>().is_ok() => inner,
        _ => hostname,
    }
}

/// Whether `hostname` is an IP address literal, accepting the bracketed IPv6
/// authority form as well as a bare address.
///
/// RFC 6066 §3 forbids literal IP addresses in SNI, and certificate identity
/// for an IP host is checked against an `iPAddress` SAN rather than a DNS name,
/// so both paths need this to answer correctly for `"[::1]"` and not just
/// `"::1"` / `"192.0.2.1"`.
pub fn hostname_is_ip_literal(hostname: &str) -> bool {
    strip_ipv6_brackets(hostname)
        .parse::<std::net::IpAddr>()
        .is_ok()
}

/// TLS ContentType constants.
pub mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
    pub const ALERT: u8 = 0x15;
    pub const HANDSHAKE: u8 = 0x16;
    pub const APPLICATION_DATA: u8 = 0x17;
}

/// TLS HandshakeType constants.
pub mod handshake_type {
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const NEW_SESSION_TICKET: u8 = 0x04;
    pub const ENCRYPTED_EXTENSIONS: u8 = 0x08;
    pub const CERTIFICATE: u8 = 0x0b;
    /// CertificateRequest (RFC 8446 Section 4.3.2).
    pub const CERTIFICATE_REQUEST: u8 = 0x0d;
    pub const CERTIFICATE_VERIFY: u8 = 0x0f;
    /// CertificateStatus (OCSP Stapling, RFC 6066 Section 8).
    /// Sent by server in TLS 1.2 between Certificate and ServerKeyExchange.
    pub const CERTIFICATE_STATUS: u8 = 0x16;
    pub const FINISHED: u8 = 0x14;
    /// CompressedCertificate (RFC 8879).
    pub const COMPRESSED_CERTIFICATE: u8 = 0x19;
    pub const KEY_UPDATE: u8 = 0x18;
    /// Synthetic message type used for HRR transcript replacement (RFC 8446 Section 4.4.1).
    pub const MESSAGE_HASH: u8 = 0xFE;
}
