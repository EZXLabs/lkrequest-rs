//! Sans-I/O tunnel state machine for MASQUE CONNECT-UDP.
//!
//! This module is the layer above [`crate::codec`]: it knows the *order* things
//! happen in — request, response validation, capsules, datagrams, close — while
//! still performing no I/O. It never opens a socket, never touches HTTP/3 and
//! never reads a clock; the caller supplies bytes, header pairs and timestamps
//! and is told what to do next.
//!
//! The seam deliberately mirrors `lktls`'s `HandshakeDriver`
//! (`start()` / `feed()` / `progress()`), with one structural difference forced
//! by the protocol: MASQUE has **two channels**, not one.
//!
//! | Channel | Reliable? | Feed in | Send out |
//! |---|---|---|---|
//! | Request stream (capsules, RFC 9297 §3) | ordered, reliable | [`TunnelDriver::feed_stream`], [`TunnelDriver::feed_stream_end`] | [`TunnelAction::SendStream`] |
//! | HTTP Datagrams (RFC 9298 §4) | unreliable, unordered, lossy | [`TunnelDriver::accept_datagram`] | [`TunnelDriver::send_payload`] |
//!
//! ## Driving one tunnel
//!
//! 1. Build a [`TunnelConfig`]. This validates the URI Template expansion up
//!    front, so a bad target is rejected before any request goes out
//!    (RFC 9298 §2).
//! 2. [`TunnelDriver::new`], then [`TunnelDriver::start`] → a
//!    [`ConnectUdpRequest`] describing the CONNECT-UDP request to send.
//! 3. [`TunnelDriver::feed_response`] with the status and headers that come
//!    back. Success is 2xx that also satisfies the requirements RFC 9298 §3.5
//!    imports from RFC 9297 §3.2 — not 204/205/206, and no `content-length`,
//!    `content-type` or `transfer-encoding`. A `capsule-protocol` response
//!    header is *recorded* rather than required
//!    ([`TunnelDriver::capsule_protocol_header`]): RFC 9297 §3.4 makes sending
//!    it a SHOULD and §3.2 does not list it, because a 2xx answer to
//!    `connect-udp` already puts the Capsule Protocol in force via the upgrade
//!    token.
//! 4. [`TunnelDriver::progress`] in a loop, exactly like the TLS driver loop.
//!    [`TunnelAction::Ready`] means datagrams may now flow.
//!
//! ```
//! use lkmasque::codec::QuarterStreamId;
//! use lkmasque::tunnel::{AuthHeader, TunnelAction, TunnelConfig, TunnelDriver};
//!
//! let config = TunnelConfig::new("proxy.example.com:443", "example.org", 443)?
//!     .with_auth(AuthHeader::proxy_authorization("Basic dXNlcjpwYXNz")?);
//!
//! let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), 1350)?;
//!
//! let request = tunnel.start()?;
//! assert_eq!(request.path, "/.well-known/masque/udp/example.org/443/");
//!
//! // ... the caller sends `request` and reads the response ...
//! tunnel.feed_response(200, [("capsule-protocol", "?1")])?;
//! assert!(matches!(tunnel.progress()?, TunnelAction::Ready));
//! assert!(tunnel.is_open());
//! # Ok::<(), lkmasque::tunnel::TunnelError>(())
//! ```
//!
//! ## Why no `http` crate
//!
//! [`ConnectUdpRequest`] is plain strings rather than `http::Request`. The
//! `:protocol` pseudo-header of RFC 8441 has no representation in `http`'s
//! types — `h3` carries it out of band in request extensions — so the type
//! would describe only part of the request while pulling every consumer of this
//! crate onto one HTTP type library. The point of keeping this crate at a
//! single dependency is that a third party can drive it from `quiche`,
//! `s2n-quic` or anything else; string pairs are what all of them can build
//! from.
//!
//! ## Many tunnels on one connection
//!
//! `read_datagram` is connection-level, so the caller needs to demultiplex.
//! [`TunnelTable`] keys tunnels by [`QuarterStreamId`] and
//! [`TunnelTable::dispatch`] turns one received datagram into "deliver these
//! payload bytes to this tunnel" or one of the two RFC-mandated drops.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use crate::codec::{
    build_connect_udp_path, classify_payload, decode_datagram, encode_datagram_into, encode_varint,
    tunnel_capacity, Capsule, CapsuleParser, CodecError, HttpDatagram, PayloadVerdict,
    QuarterStreamId, CONTEXT_ID_UDP_PAYLOAD, MAX_UDP_PAYLOAD_LEN,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The `:method` of a CONNECT-UDP request (RFC 9298 §3).
pub const CONNECT_UDP_METHOD: &str = "CONNECT";

/// The `:protocol` of a CONNECT-UDP request (RFC 9298 §3, RFC 8441 §4).
pub const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

/// The `:scheme` of a CONNECT-UDP request over an HTTPS proxy (RFC 9298 §3).
pub const CONNECT_UDP_SCHEME: &str = "https";

/// Name of the Capsule Protocol header field (RFC 9297 §3.4).
pub const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";

/// The only Capsule Protocol value that means "yes": an sf-boolean true
/// (RFC 9297 §3.4).
pub const CAPSULE_PROTOCOL_VALUE: &str = "?1";

/// Header field name used by proxies that authenticate with
/// `Proxy-Authorization` (RFC 9110 §11.7.1) — the common case.
pub const PROXY_AUTHORIZATION_HEADER: &str = "proxy-authorization";

/// Header field name used by deployments that authenticate with
/// `Authorization` (RFC 9110 §11.6.2), such as the `masque-go` examples and
/// RFC 9484 §11.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Default ceiling on the Capsule Value this reader will reassemble.
///
/// A capsule may declare a length up to `2^62 - 1`, so an incremental reader
/// needs a bound of its own. A capsule declaring more than this is **stepped
/// over without being buffered** rather than failing the tunnel, which is what
/// RFC 9297 §3.2 and RFC 9298 §5 ask for; see
/// [`TunnelConfig::with_max_stream_buffer`].
///
/// 128 KiB, chosen against what a legal capsule can actually be rather than as
/// a round number. A DATAGRAM capsule carrying the largest permitted UDP
/// payload holds a Context ID varint plus [`MAX_UDP_PAYLOAD_LEN`] bytes, and
/// RFC 9000 §16 allows that varint to be encoded non-minimally in up to 8
/// bytes — so a Value of 65535 bytes is within the specification. The previous
/// 64 KiB left 9 bytes of headroom over `MAX_UDP_PAYLOAD_LEN` and would have
/// skipped it.
pub const DEFAULT_MAX_STREAM_BUFFER: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A tunnel-level failure.
///
/// Most variants are *fatal*: they move the tunnel to
/// [`TunnelState::Failed`] and every later [`TunnelDriver::progress`] returns
/// the same error, so a caller cannot accidentally keep using a tunnel the
/// protocol has already ended. The exceptions are documented per variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// A wire-format failure from [`crate::codec`].
    ///
    /// Not fatal on its own: a damaged datagram is dropped, because datagrams
    /// are unreliable anyway. Capsule damage arrives as
    /// [`TunnelError::MalformedCapsule`] instead.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// The proxy answered with a non-2xx status, so the tunnel was refused
    /// (RFC 9298 §3.1, §3.5). Fatal.
    #[error("MASQUE proxy rejected CONNECT-UDP with status {status}")]
    RejectedStatus {
        /// The status code the proxy returned.
        status: u16,
    },

    /// The response was 2xx but violates one of the requirements RFC 9297
    /// §3.2 places on a response that starts the Capsule Protocol, which
    /// RFC 9298 §3.5 requires the client to treat as a failed attempt. Fatal.
    ///
    /// Note what is *not* here: a missing or false `capsule-protocol` response
    /// header. That header is a SHOULD (RFC 9297 §3.4) and is not among §3.2's
    /// requirements, so its absence is an observation
    /// ([`TunnelDriver::capsule_protocol_header`]), not a failure.
    #[error("MASQUE proxy response cannot start the Capsule Protocol: {reason}")]
    MalformedResponse {
        /// Which requirement was violated.
        reason: MalformedResponseReason,
    },

    /// The capsule stream was damaged or ended mid-capsule, which RFC 9297
    /// §3.3 requires be treated as a malformed message. Fatal.
    #[error("malformed capsule stream: {0}")]
    MalformedCapsule(CodecError),

    /// The caller asked to send a payload longer than [`MAX_UDP_PAYLOAD_LEN`],
    /// which RFC 9298 §5 forbids sending. **Not fatal**: nothing reached the
    /// wire, so the tunnel stays usable and the caller simply drops the
    /// payload.
    #[error("UDP payload of {payload_len} bytes exceeds the {MAX_UDP_PAYLOAD_LEN}-byte maximum")]
    PayloadTooLarge {
        /// Length of the payload that was refused.
        payload_len: usize,
    },

    /// The peer sent a payload longer than [`MAX_UDP_PAYLOAD_LEN`]. RFC 9298
    /// §5 requires the receiver to abort the request stream, so this is fatal
    /// and the caller must reset the stream rather than finish it.
    #[error("peer sent a UDP payload of {payload_len} bytes; the request stream must be aborted")]
    PeerPayloadTooLarge {
        /// Length of the offending payload.
        payload_len: usize,
    },

    /// A datagram carrying another tunnel's Quarter Stream ID was handed to
    /// this tunnel. **Not fatal**; it means the caller's demultiplexing is
    /// wrong. Use [`TunnelTable::dispatch`] to avoid it.
    #[error("datagram is for quarter stream {actual:?}, not {expected:?}")]
    WrongTunnel {
        /// The Quarter Stream ID this tunnel owns.
        expected: QuarterStreamId,
        /// The Quarter Stream ID found in the datagram.
        actual: QuarterStreamId,
    },

    /// The operation is not allowed in the tunnel's current state, e.g. sending
    /// a payload before the response arrived. **Not fatal**; it is a caller
    /// sequencing bug, not a protocol event.
    #[error("operation is not valid while the tunnel is {state:?}")]
    InvalidState {
        /// The state the tunnel was in when the operation was attempted.
        state: TunnelState,
    },

    /// A tunnel with this Quarter Stream ID is already in the
    /// [`TunnelTable`].
    #[error("a tunnel is already registered for quarter stream {quarter_stream_id:?}")]
    DuplicateTunnel {
        /// The key that was already taken.
        quarter_stream_id: QuarterStreamId,
    },

    /// The proxy authority was empty, so no `:authority` could be built
    /// (RFC 9298 §3).
    #[error("MASQUE proxy authority must not be empty")]
    EmptyProxyAuthority,

    /// A header field name was empty, contained a character outside the
    /// `token` grammar, or was not lowercase as HTTP/3 requires
    /// (RFC 9110 §5.1, RFC 9114 §4.2).
    #[error("invalid header field name {name:?}")]
    InvalidHeaderName {
        /// The rejected name.
        name: String,
    },

    /// A header field value contained a control character or had leading or
    /// trailing whitespace (RFC 9110 §5.5).
    #[error("invalid value for header field {name:?}")]
    InvalidHeaderValue {
        /// Name of the field whose value was rejected.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

/// Whether `name` is a valid lowercase HTTP field name (RFC 9110 §5.1).
///
/// HTTP/3 requires field names to be lowercase (RFC 9114 §4.2), and pseudo
/// headers are built by [`ConnectUdpRequest`] itself, so a leading `:` is
/// rejected here too.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Whether `value` is a valid HTTP field value (RFC 9110 §5.5).
fn is_valid_header_value(value: &str) -> bool {
    if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
        return false;
    }
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

fn checked_header(name: String, value: String) -> Result<(String, String), TunnelError> {
    if !is_valid_header_name(&name) {
        return Err(TunnelError::InvalidHeaderName { name });
    }
    if !is_valid_header_value(&value) {
        return Err(TunnelError::InvalidHeaderValue { name });
    }
    Ok((name, value))
}

/// Why a 2xx response cannot start the Capsule Protocol (RFC 9297 §3.2).
///
/// Each variant names a requirement whose text ends "A receiver that observes
/// a violation of these requirements MUST treat the HTTP message as
/// malformed", so both are genuine protocol failures rather than strictness
/// this crate chose to add.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedResponseReason {
    /// The status was 204, 205 or 206, which RFC 9297 §3.2 forbids on a
    /// response that uses the Capsule Protocol.
    ForbiddenStatus {
        /// The status the proxy returned.
        status: u16,
    },
    /// The response carried `content-length`, `content-type` or
    /// `transfer-encoding`. RFC 9297 §3.2 forbids all three, because the data
    /// stream of such a message carries HTTP content rather than capsules.
    ForbiddenHeader {
        /// The offending field name, lowercase.
        name: &'static str,
    },
}

impl fmt::Display for MalformedResponseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenStatus { status } => write!(
                f,
                "status {status} must not be sent on a Capsule Protocol response (RFC 9297 §3.2)"
            ),
            Self::ForbiddenHeader { name } => write!(
                f,
                "the response carries `{name}`, which RFC 9297 §3.2 forbids on a Capsule Protocol \
                 response"
            ),
        }
    }
}

/// What the response said about the `capsule-protocol` header field.
///
/// This is an **observation, not a verdict**. RFC 9297 §3.4 makes sending the
/// header a SHOULD ("to simplify intermediary processing"), and the
/// requirements RFC 9298 §3.5 actually imports — RFC 9297 §3.2 — do not
/// mention it. For a 2xx answer to `connect-udp` the Capsule Protocol is
/// already in force by virtue of the upgrade token, which §3.2 says an
/// intermediary may rely on instead of the header. So a tunnel opens in every
/// case below; the distinction exists so the caller can log what it actually
/// saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapsuleProtocolHeader {
    /// Present and true (`?1`), which is what a proxy following the SHOULD
    /// sends.
    Present,
    /// Absent. Within the specification, and not this client's business to
    /// refuse.
    Absent,
    /// Present with a value that is not `?1`, most often `?0`. RFC 9297 §3.4:
    /// "A Capsule-Protocol header field with a false value has the same
    /// semantics as when the header is not present."
    NotTrue,
    /// Present more than once. RFC 9297 §3.4 spells this case out: the field's
    /// type becomes a List rather than a Boolean, so it "MUST be handled as if
    /// the field were not present". Taking the last occurrence, which is what
    /// a naive loop does, is what this variant exists to prevent.
    Repeated,
}

/// The field names RFC 9297 §3.2 forbids on a Capsule Protocol message.
const FORBIDDEN_RESPONSE_HEADERS: [&str; 3] =
    ["content-length", "content-type", "transfer-encoding"];

/// Whether a `capsule-protocol` field value means "true" (RFC 9297 §3.4).
///
/// The value is a Structured Fields Item holding a boolean, so surrounding
/// whitespace and trailing parameters are tolerated and only the bare item is
/// compared. Anything other than `?1` — including `?0` — means the Capsule
/// Protocol was not negotiated.
fn capsule_protocol_is_true(value: &str) -> bool {
    let item = value.split(';').next().unwrap_or("").trim();
    item == CAPSULE_PROTOCOL_VALUE
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// One authentication header to attach to the CONNECT-UDP request.
///
/// RFC 9298 §7 says nothing normative about authentication, and deployments do
/// not agree: Bright Data sends `proxy-authorization: Basic …`, Cloudflare uses
/// `Preshared` or `PrivateToken`, INVISV uses `PrivacyToken`, while `masque-go`
/// and RFC 9484 §11 use `Authorization`. Both the field name and the credential
/// syntax are therefore caller-chosen, and this type carries them verbatim.
///
/// The credential is already encoded — this crate deliberately does no base64,
/// which would be a dependency for one line of a policy that belongs to the
/// caller anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHeader {
    name: String,
    value: String,
}

impl AuthHeader {
    /// An arbitrary authentication header.
    ///
    /// `name` must be a lowercase HTTP field name, as HTTP/3 requires
    /// (RFC 9114 §4.2).
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, TunnelError> {
        let (name, value) = checked_header(name.into(), value.into())?;
        Ok(Self { name, value })
    }

    /// `proxy-authorization: <credentials>` (RFC 9110 §11.7.1).
    ///
    /// `credentials` is the complete field value including the scheme, e.g.
    /// `"Basic dXNlcjpwYXNz"` or `"Preshared abc123"`.
    pub fn proxy_authorization(credentials: impl Into<String>) -> Result<Self, TunnelError> {
        Self::new(PROXY_AUTHORIZATION_HEADER, credentials)
    }

    /// `authorization: <credentials>` (RFC 9110 §11.6.2), for deployments that
    /// expect the end-to-end field instead.
    pub fn authorization(credentials: impl Into<String>) -> Result<Self, TunnelError> {
        Self::new(AUTHORIZATION_HEADER, credentials)
    }

    /// The field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything needed to ask a proxy for one CONNECT-UDP tunnel.
///
/// Construction validates the URI Template expansion, so RFC 9298 §2's "abort
/// rather than send a request built from an invalid template" is enforced
/// before a driver can exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    proxy_authority: String,
    target_host: String,
    target_port: u16,
    path: String,
    auth: Option<AuthHeader>,
    extra_headers: Vec<(String, String)>,
    max_stream_buffer: usize,
}

impl TunnelConfig {
    /// Describe a tunnel from `proxy_authority` to `target_host:target_port`.
    ///
    /// `proxy_authority` becomes `:authority` and is normally `host:port` of
    /// the MASQUE proxy. The target is expanded into the `:path` through
    /// [`build_connect_udp_path`], which percent-encodes IPv6 literals and
    /// rejects an empty host or a zero port (RFC 9298 §3).
    pub fn new(
        proxy_authority: impl Into<String>,
        target_host: impl Into<String>,
        target_port: u16,
    ) -> Result<Self, TunnelError> {
        let proxy_authority = proxy_authority.into();
        if proxy_authority.is_empty() {
            return Err(TunnelError::EmptyProxyAuthority);
        }
        let target_host = target_host.into();
        let path = build_connect_udp_path(&target_host, target_port)?;
        Ok(Self {
            proxy_authority,
            target_host,
            target_port,
            path,
            auth: None,
            extra_headers: Vec::new(),
            max_stream_buffer: DEFAULT_MAX_STREAM_BUFFER,
        })
    }

    /// Attach an authentication header (replacing any previous one).
    #[must_use]
    pub fn with_auth(mut self, auth: AuthHeader) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Attach an extra request header, e.g. a deployment-specific routing
    /// field. Names must be lowercase (RFC 9114 §4.2).
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, TunnelError> {
        self.extra_headers
            .push(checked_header(name.into(), value.into())?);
        Ok(self)
    }

    /// Override [`DEFAULT_MAX_STREAM_BUFFER`], the largest Capsule Value this
    /// tunnel will reassemble.
    ///
    /// A capsule declaring more than this is skipped without being buffered
    /// and counted in [`TunnelStats::capsules_skipped_over_limit`]; it is not
    /// an error, so lowering this trades capsules you would have received for
    /// memory, and never costs you the tunnel. Holding is therefore bounded by
    /// this value plus one capsule header, whatever the peer sends.
    #[must_use]
    pub fn with_max_stream_buffer(mut self, bytes: usize) -> Self {
        self.max_stream_buffer = bytes;
        self
    }

    /// The `:authority` this tunnel will request.
    pub fn proxy_authority(&self) -> &str {
        &self.proxy_authority
    }

    /// The tunnel's target host, as given.
    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    /// The tunnel's target port.
    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    /// The validated `:path` (RFC 9298 §3).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The authentication header, if one was configured.
    pub fn auth(&self) -> Option<&AuthHeader> {
        self.auth.as_ref()
    }

    /// The capsule reassembly ceiling in bytes.
    pub fn max_stream_buffer(&self) -> usize {
        self.max_stream_buffer
    }

    /// Build the structured CONNECT-UDP request description (RFC 9298 §3).
    ///
    /// Header order is fixed: `capsule-protocol` first (RFC 9297 §3.4), then
    /// authentication, then any extra headers in the order they were added.
    pub fn build_request(&self) -> ConnectUdpRequest {
        let mut headers = Vec::with_capacity(2 + self.extra_headers.len());
        headers.push((
            CAPSULE_PROTOCOL_HEADER.to_string(),
            CAPSULE_PROTOCOL_VALUE.to_string(),
        ));
        if let Some(auth) = &self.auth {
            headers.push((auth.name.clone(), auth.value.clone()));
        }
        headers.extend(self.extra_headers.iter().cloned());

        ConnectUdpRequest {
            method: CONNECT_UDP_METHOD,
            protocol: CONNECT_UDP_PROTOCOL,
            scheme: CONNECT_UDP_SCHEME,
            authority: self.proxy_authority.clone(),
            path: self.path.clone(),
            headers,
        }
    }
}

/// A CONNECT-UDP request, described rather than serialized (RFC 9298 §3).
///
/// The caller turns this into whatever its HTTP/3 library wants. In particular
/// `protocol` is the RFC 8441 `:protocol` pseudo-header, which `h3` takes
/// through request extensions rather than the header map — the reason this
/// crate hands over strings instead of an `http::Request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    /// `:method`, always [`CONNECT_UDP_METHOD`].
    pub method: &'static str,
    /// `:protocol`, always [`CONNECT_UDP_PROTOCOL`] (RFC 8441 §4).
    pub protocol: &'static str,
    /// `:scheme`, always [`CONNECT_UDP_SCHEME`].
    pub scheme: &'static str,
    /// `:authority` — the MASQUE proxy.
    pub authority: String,
    /// `:path` — the expanded URI Template carrying the target.
    pub path: String,
    /// Ordinary request headers, lowercase names, in send order.
    pub headers: Vec<(String, String)>,
}

impl ConnectUdpRequest {
    /// Look up a header by name, which is already lowercase.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// Capsules, actions, lifecycle
// ---------------------------------------------------------------------------

/// An owned copy of one parsed capsule (RFC 9297 §3.2).
///
/// Owned rather than borrowed because a capsule may span several reads of the
/// request stream, so the bytes it was assembled from are gone by the time the
/// caller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCapsule {
    /// Capsule Type field.
    pub capsule_type: u64,
    /// Capsule Value field.
    pub value: Vec<u8>,
}

impl From<Capsule<'_>> for OwnedCapsule {
    fn from(capsule: Capsule<'_>) -> Self {
        Self {
            capsule_type: capsule.capsule_type,
            value: capsule.value.to_vec(),
        }
    }
}

/// Where a tunnel is in its life (RFC 9298 §3, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// The request has not been sent yet, or the response has not arrived.
    /// Datagrams must not flow.
    Connecting,
    /// The response was accepted: datagrams may flow in both directions.
    Open,
    /// A local close was requested. The caller still has to finish the request
    /// stream; [`TunnelDriver::progress`] will tell it to.
    Closing,
    /// The request stream is done in both directions. Nothing more happens.
    Closed,
    /// The tunnel failed. [`TunnelDriver::failure`] holds the reason and
    /// [`TunnelDriver::progress`] keeps returning it.
    Failed,
}

/// What the caller should do next, returned by [`TunnelDriver::progress`].
///
/// The fifth outcome — failure — is the `Err` arm of `progress`'s `Result`,
/// matching `lktls`'s driver, so failure cannot be confused with a state the
/// loop is allowed to continue from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelAction {
    /// Write these bytes to the request stream, then call `progress` again.
    SendStream(Vec<u8>),
    /// The response was accepted: the tunnel is open and datagrams may flow
    /// (RFC 9298 §3.5). Emitted once.
    Ready,
    /// A complete capsule arrived. Unknown Capsule Types are still reported
    /// here; RFC 9297 §3.2 lets the caller ignore them, and the framing has
    /// already been skipped correctly either way.
    Capsule(OwnedCapsule),
    /// Nothing to do until more input arrives — feed the request stream or a
    /// datagram, then call `progress` again.
    NeedData,
    /// The tunnel is finished. Finish the request stream (a normal FIN, not a
    /// reset) and unregister the tunnel from its [`TunnelTable`].
    Closed,
}

/// What [`TunnelDriver::send_payload`] decided about one outbound payload
/// (RFC 9298 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// An encoded HTTP Datagram payload; hand it to the outer connection.
    Send(Vec<u8>),
    /// Larger than the tunnel can currently carry, so it was discarded as UDP
    /// semantics allow. This is not an error, and the drop has been counted in
    /// [`TunnelStats::dropped_over_capacity`].
    Dropped {
        /// Length of the discarded payload.
        payload_len: usize,
        /// The capacity it did not fit in.
        capacity: usize,
    },
}

impl SendOutcome {
    /// The encoded datagram, or `None` when the payload was dropped.
    pub fn datagram(&self) -> Option<&[u8]> {
        match self {
            SendOutcome::Send(bytes) => Some(bytes),
            SendOutcome::Dropped { .. } => None,
        }
    }
}

/// Counters a caller can surface for diagnostics.
///
/// The two drop counters are kept apart on purpose: one is an MTU problem and
/// the other is a proxy sending contexts that were never registered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelStats {
    /// Datagrams handed out by [`TunnelDriver::send_payload`].
    pub datagrams_sent: u64,
    /// Payload bytes handed out by [`TunnelDriver::send_payload`].
    pub payload_bytes_sent: u64,
    /// Datagrams accepted by [`TunnelDriver::accept_datagram`].
    pub datagrams_received: u64,
    /// Payload bytes accepted by [`TunnelDriver::accept_datagram`].
    pub payload_bytes_received: u64,
    /// Payloads discarded because they exceeded the tunnel capacity
    /// (RFC 9298 §5).
    pub dropped_over_capacity: u64,
    /// Datagrams discarded because their Context ID was not 0 (RFC 9298 §5).
    /// Never an error.
    pub dropped_unknown_context: u64,
    /// Capsules parsed off the request stream.
    pub capsules_received: u64,
    /// Capsules stepped over because their declared Length exceeded
    /// [`TunnelConfig::max_stream_buffer`]. Never an error: RFC 9297 §3.2 has
    /// a receiver drop and skip a capsule it cannot use, and RFC 9298 §5 asks
    /// that it be discarded without buffering the contents.
    pub capsules_skipped_over_limit: u64,
}

// ---------------------------------------------------------------------------
// TunnelDriver
// ---------------------------------------------------------------------------

/// The state machine for one CONNECT-UDP tunnel.
///
/// See the [module documentation](self) for the driving loop. Nothing here
/// performs I/O or reads a clock: timestamps arrive through
/// [`TunnelDriver::touch`].
#[derive(Debug, Clone)]
pub struct TunnelDriver {
    config: TunnelConfig,
    quarter_stream_id: QuarterStreamId,
    state: TunnelState,
    failure: Option<TunnelError>,
    started: bool,
    ready_pending: bool,
    close_reported: bool,
    max_datagram_size: usize,
    capacity: usize,
    stream_buf: Vec<u8>,
    /// Bytes of an over-large capsule's Value still to be discarded.
    /// Non-zero means the parser is stepping over a capsule it declined to
    /// reassemble; see `feed_stream`.
    skip_remaining: u64,
    capsules: VecDeque<OwnedCapsule>,
    pending_stream_out: Vec<u8>,
    last_activity: Option<Instant>,
    capsule_protocol_header: CapsuleProtocolHeader,
    stats: TunnelStats,
}

impl TunnelDriver {
    /// Create a tunnel for the request stream identified by
    /// `quarter_stream_id` (RFC 9297 §2.1).
    ///
    /// `max_datagram_size` is the outer connection's current maximum datagram
    /// size; the inner MTU is derived from it and can be revised later with
    /// [`TunnelDriver::set_max_datagram_size`]. The Quarter Stream ID must fit
    /// a QUIC varint, so an unencodable value is rejected here rather than at
    /// first send.
    ///
    /// The tunnel starts in [`TunnelState::Connecting`]; call
    /// [`TunnelDriver::start`] to get the request to send.
    pub fn new(
        config: TunnelConfig,
        quarter_stream_id: QuarterStreamId,
        max_datagram_size: usize,
    ) -> Result<Self, TunnelError> {
        let capacity =
            tunnel_capacity(max_datagram_size, quarter_stream_id, CONTEXT_ID_UDP_PAYLOAD)?;
        Ok(Self {
            config,
            quarter_stream_id,
            state: TunnelState::Connecting,
            failure: None,
            started: false,
            ready_pending: false,
            close_reported: false,
            max_datagram_size,
            capacity,
            stream_buf: Vec::new(),
            skip_remaining: 0,
            capsules: VecDeque::new(),
            pending_stream_out: Vec::new(),
            last_activity: None,
            capsule_protocol_header: CapsuleProtocolHeader::Absent,
            stats: TunnelStats::default(),
        })
    }

    // -- introspection -----------------------------------------------------

    /// The configuration this tunnel was built from.
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// The Quarter Stream ID datagrams for this tunnel carry (RFC 9297 §2.1).
    pub fn quarter_stream_id(&self) -> QuarterStreamId {
        self.quarter_stream_id
    }

    /// The current lifecycle state.
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Whether datagrams may flow right now.
    pub fn is_open(&self) -> bool {
        matches!(self.state, TunnelState::Open)
    }

    /// The failure that ended this tunnel, if any.
    pub fn failure(&self) -> Option<&TunnelError> {
        self.failure.as_ref()
    }

    /// Counters for diagnostics.
    pub fn stats(&self) -> TunnelStats {
        self.stats
    }

    /// What the response said about `capsule-protocol` (RFC 9297 §3.4).
    ///
    /// Meaningful only once [`TunnelDriver::feed_response`] has accepted a
    /// response; before that it reads [`CapsuleProtocolHeader::Absent`].
    ///
    /// Nothing in this crate branches on it — it is here so the caller, which
    /// is the layer with a logger, can report what the proxy actually sent.
    /// Anything other than [`CapsuleProtocolHeader::Present`] is worth a line
    /// in a log: the tunnel is fine, but a proxy skipping a SHOULD is the kind
    /// of detail that explains a later surprise.
    pub fn capsule_protocol_header(&self) -> CapsuleProtocolHeader {
        self.capsule_protocol_header
    }

    // -- handshake ---------------------------------------------------------

    /// Produce the CONNECT-UDP request to send (RFC 9298 §3).
    ///
    /// The analogue of `lktls`'s `HandshakeDriver::start`, except that HTTP/3
    /// sends a header block rather than bytes, so this returns a structured
    /// [`ConnectUdpRequest`]. Calling it twice is a sequencing error and
    /// yields [`TunnelError::InvalidState`].
    pub fn start(&mut self) -> Result<ConnectUdpRequest, TunnelError> {
        self.check_live()?;
        if self.started || self.state != TunnelState::Connecting {
            return Err(TunnelError::InvalidState { state: self.state });
        }
        self.started = true;
        Ok(self.config.build_request())
    }

    /// Feed the response status and headers (RFC 9298 §3.5).
    ///
    /// Success requires a 2xx status other than 204/205/206 and no
    /// Content-Length, Content-Type, or Transfer-Encoding response field.
    /// The optional `capsule-protocol` field is recorded but does not decide
    /// whether the tunnel opens. A malformed response moves the tunnel to
    /// [`TunnelState::Failed`] and returns the reason.
    ///
    /// Header names are matched case-insensitively even though HTTP/3 requires
    /// them lowercase, because being strict about a peer's casing would turn a
    /// cosmetic deviation into a tunnel failure.
    pub fn feed_response<'h, I>(&mut self, status: u16, headers: I) -> Result<(), TunnelError>
    where
        I: IntoIterator<Item = (&'h str, &'h str)>,
    {
        self.check_live()?;
        if !self.started || self.state != TunnelState::Connecting {
            return Err(TunnelError::InvalidState { state: self.state });
        }

        // One pass: count the `capsule-protocol` occurrences (the count is
        // what decides §3.4's List case) and note the first forbidden field.
        let mut capsule_protocol_seen = 0_usize;
        let mut capsule_protocol_value: Option<String> = None;
        let mut forbidden: Option<&'static str> = None;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(CAPSULE_PROTOCOL_HEADER) {
                capsule_protocol_seen += 1;
                capsule_protocol_value = Some(value.to_string());
            } else if forbidden.is_none() {
                forbidden = FORBIDDEN_RESPONSE_HEADERS
                    .iter()
                    .find(|candidate| name.eq_ignore_ascii_case(candidate))
                    .copied();
            }
        }

        if !(200..300).contains(&status) {
            return Err(self.fail(TunnelError::RejectedStatus { status }));
        }

        // The two requirements RFC 9298 §3.5 imports from RFC 9297 §3.2, both
        // of which end "MUST treat the HTTP message as malformed". A 200 with
        // `content-length` is the one that shows up in practice: frameworks
        // add it to a bodyless response, and accepting it would leave us
        // parsing an HTTP content stream as capsules and blaming the capsule
        // framing for it.
        // 204 (No Content), 205 (Reset Content) and 206 (Partial Content) —
        // contiguous, so written as a range to keep clippy quiet.
        if matches!(status, 204..=206) {
            return Err(self.fail(TunnelError::MalformedResponse {
                reason: MalformedResponseReason::ForbiddenStatus { status },
            }));
        }
        if let Some(name) = forbidden {
            return Err(self.fail(TunnelError::MalformedResponse {
                reason: MalformedResponseReason::ForbiddenHeader { name },
            }));
        }

        // `capsule-protocol` is recorded, never enforced. See
        // [`CapsuleProtocolHeader`] for why refusing a proxy that omits a
        // SHOULD-level header would be this client's mistake, not the proxy's.
        self.capsule_protocol_header = if capsule_protocol_seen > 1 {
            CapsuleProtocolHeader::Repeated
        } else {
            match capsule_protocol_value.as_deref() {
                Some(value) if capsule_protocol_is_true(value) => CapsuleProtocolHeader::Present,
                Some(_) => CapsuleProtocolHeader::NotTrue,
                None => CapsuleProtocolHeader::Absent,
            }
        };

        self.state = TunnelState::Open;
        self.ready_pending = true;
        Ok(())
    }

    // -- request stream (capsules) -----------------------------------------

    /// Feed bytes read from the request stream (RFC 9297 §3.2).
    ///
    /// The stream arrives incrementally while [`CapsuleParser`] reads a buffer
    /// as a whole stream, so this method owns the reassembly: bytes are
    /// appended to an internal buffer, every *complete* capsule at its head is
    /// parsed off and queued for [`TunnelDriver::progress`], and the partial
    /// tail stays buffered for the next call. A truncated tail is therefore not
    /// an error here — only at [`TunnelDriver::feed_stream_end`], where
    /// RFC 9297 §3.3 makes it a malformed message.
    ///
    /// Damage that cannot be explained by "more bytes are coming", and a tail
    /// that grows past [`TunnelConfig::max_stream_buffer`], fail the tunnel.
    pub fn feed_stream(&mut self, data: &[u8]) -> Result<(), TunnelError> {
        self.check_live()?;
        if !matches!(self.state, TunnelState::Open | TunnelState::Closing) {
            return Err(TunnelError::InvalidState { state: self.state });
        }

        self.stream_buf.extend_from_slice(data);

        let mut parsed: Vec<OwnedCapsule> = Vec::new();
        let limit = self.config.max_stream_buffer as u64;

        loop {
            // Finish discarding an over-large capsule before looking for the
            // next header. This is the state that keeps the buffer bounded
            // without ending the tunnel.
            if self.skip_remaining > 0 {
                let take = self.skip_remaining.min(self.stream_buf.len() as u64) as usize;
                self.stream_buf.drain(..take);
                self.skip_remaining -= take as u64;
                if self.skip_remaining > 0 {
                    // Buffer is empty and more of the value is still coming.
                    break;
                }
                continue;
            }

            let header = {
                let parser = CapsuleParser::new(&self.stream_buf);
                match parser.peek_header() {
                    Ok(Some(header)) => header,
                    // Exactly exhausted, or the header itself has not fully
                    // arrived: the stream is open, so wait for more.
                    Ok(None) | Err(CodecError::Truncated { .. }) => break,
                    Err(err) => return Err(self.fail(TunnelError::MalformedCapsule(err))),
                }
            };

            // A capsule too large to reassemble is skipped, not fatal.
            //
            // RFC 9297 §3.2 requires that an unknown Capsule Type be silently
            // dropped and skipped over, and RFC 9298 §5 asks that an
            // over-large DATAGRAM capsule be discarded "without buffering the
            // capsule contents". Failing the tunnel here — which is what this
            // used to do once the residue passed `max_stream_buffer` — was the
            // opposite of both, and it reset the request stream, killed the
            // inner QUIC connection and quarantined the route. A single
            // capsule we have no use for should cost nothing.
            //
            // It also made the outcome depend on how the peer chopped up its
            // writes, since the old check looked at leftover bytes rather than
            // at the declared length: the same byte sequence passed in one
            // `feed_stream` call and failed across several.
            if header.length > limit {
                self.stream_buf.drain(..header.header_len);
                self.skip_remaining = header.length;
                self.stats.capsules_skipped_over_limit += 1;
                continue;
            }

            if header.length > (self.stream_buf.len() - header.header_len) as u64 {
                // Reassembling, and bounded: `header.length <= limit`, so this
                // holds at most `limit` plus one capsule header.
                break;
            }

            // The capsule is copied out inside this block so the borrow of
            // `stream_buf` ends before the buffer is drained or `self.fail` is
            // called.
            let outcome = {
                let mut parser = CapsuleParser::new(&self.stream_buf);
                match parser.next_capsule() {
                    Ok(Some(capsule)) => Ok(Some((OwnedCapsule::from(capsule), parser.offset()))),
                    Ok(None) => Ok(None),
                    Err(err) => Err(err),
                }
            };
            match outcome {
                Ok(Some((capsule, consumed))) => {
                    parsed.push(capsule);
                    self.stream_buf.drain(..consumed);
                }
                // `peek_header` already established there is a capsule here
                // and that all of it is buffered, so neither of these is
                // reachable. Treat them as damage rather than asserting.
                Ok(None) => break,
                Err(err) => return Err(self.fail(TunnelError::MalformedCapsule(err))),
            }
        }

        self.stats.capsules_received += parsed.len() as u64;
        self.capsules.extend(parsed);
        Ok(())
    }

    /// Signal that the peer finished the request stream.
    ///
    /// Bytes left over mean a capsule was cut in half, which RFC 9297 §3.3
    /// requires be treated as a malformed message, so the tunnel fails.
    /// Otherwise the tunnel moves to [`TunnelState::Closed`] and any capsules
    /// already parsed are still delivered by [`TunnelDriver::progress`] before
    /// [`TunnelAction::Closed`].
    pub fn feed_stream_end(&mut self) -> Result<(), TunnelError> {
        self.check_live()?;
        // Ending mid-skip is still a truncated capsule. Skipping an over-large
        // capsule is a decision not to *deliver* it, not a decision to stop
        // tracking the stream's framing — so RFC 9297 §3.3 applies here as it
        // does to a half-received capsule we meant to keep: the last capsule
        // was cut short, and that "MUST be treated as if it were a malformed
        // or incomplete message".
        if self.skip_remaining > 0 {
            let needed = self.skip_remaining;
            self.skip_remaining = 0;
            self.stream_buf.clear();
            return Err(
                self.fail(TunnelError::MalformedCapsule(CodecError::Truncated {
                    field: "skipped capsule value",
                    needed: usize::try_from(needed).unwrap_or(usize::MAX),
                })),
            );
        }
        if !self.stream_buf.is_empty() {
            let needed = self.stream_buf.len();
            self.stream_buf.clear();
            return Err(
                self.fail(TunnelError::MalformedCapsule(CodecError::Truncated {
                    field: "capsule",
                    needed,
                })),
            );
        }
        self.state = TunnelState::Closed;
        Ok(())
    }

    /// Queue a capsule to be written to the request stream (RFC 9297 §3.2).
    ///
    /// The bytes come back out of [`TunnelDriver::progress`] as
    /// [`TunnelAction::SendStream`]. No capsule type is required for
    /// CONNECT-UDP over HTTP/3 — datagrams travel as QUIC DATAGRAM frames —
    /// so this exists for extensions and for callers that need to speak a
    /// capsule type this crate does not model.
    pub fn queue_capsule(&mut self, capsule_type: u64, value: &[u8]) -> Result<(), TunnelError> {
        self.check_live()?;
        if !self.started || !matches!(self.state, TunnelState::Connecting | TunnelState::Open) {
            return Err(TunnelError::InvalidState { state: self.state });
        }
        encode_varint(capsule_type, &mut self.pending_stream_out)?;
        encode_varint(value.len() as u64, &mut self.pending_stream_out)?;
        self.pending_stream_out.extend_from_slice(value);
        Ok(())
    }

    // -- datagrams ---------------------------------------------------------

    /// Encode one outbound UDP payload (RFC 9298 §4, §5).
    ///
    /// The two size limits of RFC 9298 §5 are kept distinct, because they
    /// demand opposite responses:
    ///
    /// - over [`MAX_UDP_PAYLOAD_LEN`] → [`TunnelError::PayloadTooLarge`]. A
    ///   sender MUST NOT put it on the wire. The tunnel is *not* failed, since
    ///   nothing was sent.
    /// - over the current [`TunnelDriver::capacity`] →
    ///   [`SendOutcome::Dropped`]. An ordinary MTU discard, counted, not an
    ///   error.
    pub fn send_payload(&mut self, payload: &[u8]) -> Result<SendOutcome, TunnelError> {
        self.check_live()?;
        if self.state != TunnelState::Open {
            return Err(TunnelError::InvalidState { state: self.state });
        }

        match classify_payload(payload.len(), self.capacity) {
            PayloadVerdict::RejectOverProtocolMax { payload_len } => {
                Err(TunnelError::PayloadTooLarge { payload_len })
            }
            PayloadVerdict::DropOverCapacity {
                payload_len,
                capacity,
            } => {
                self.stats.dropped_over_capacity += 1;
                Ok(SendOutcome::Dropped {
                    payload_len,
                    capacity,
                })
            }
            PayloadVerdict::Sendable => {
                let mut out = Vec::with_capacity(self.max_datagram_size.max(payload.len() + 2));
                encode_datagram_into(
                    self.quarter_stream_id,
                    CONTEXT_ID_UDP_PAYLOAD,
                    payload,
                    &mut out,
                )?;
                self.stats.datagrams_sent += 1;
                self.stats.payload_bytes_sent += payload.len() as u64;
                Ok(SendOutcome::Send(out))
            }
        }
    }

    /// Accept one inbound datagram addressed to this tunnel (RFC 9298 §4, §5).
    ///
    /// Returns the UDP payload, or `None` when the datagram was dropped
    /// because its Context ID is not 0 — RFC 9298 §5 says a receiver SHALL
    /// drop an unknown context and MUST NOT treat it as an error, so the drop
    /// is only counted in [`TunnelStats::dropped_unknown_context`].
    ///
    /// A payload over [`MAX_UDP_PAYLOAD_LEN`] fails the tunnel with
    /// [`TunnelError::PeerPayloadTooLarge`]; RFC 9298 §5 requires the receiver
    /// to abort the request stream in that case, so the caller must reset it
    /// rather than finish it.
    ///
    /// Use [`TunnelTable::dispatch`] when several tunnels share one
    /// connection; a datagram for a different Quarter Stream ID is reported as
    /// [`TunnelError::WrongTunnel`] rather than silently accepted.
    pub fn accept_datagram<'d>(
        &mut self,
        datagram: &'d [u8],
    ) -> Result<Option<&'d [u8]>, TunnelError> {
        let decoded = decode_datagram(datagram)?;
        if decoded.quarter_stream_id() != self.quarter_stream_id {
            return Err(TunnelError::WrongTunnel {
                expected: self.quarter_stream_id,
                actual: decoded.quarter_stream_id(),
            });
        }
        self.accept_decoded(decoded)
    }

    fn accept_decoded<'d>(
        &mut self,
        decoded: HttpDatagram<'d>,
    ) -> Result<Option<&'d [u8]>, TunnelError> {
        self.check_live()?;
        if !matches!(self.state, TunnelState::Open | TunnelState::Closing) {
            return Err(TunnelError::InvalidState { state: self.state });
        }

        match decoded {
            HttpDatagram::UnknownContext { .. } => {
                self.stats.dropped_unknown_context += 1;
                Ok(None)
            }
            HttpDatagram::UdpPayload { payload, .. } => {
                if payload.len() > MAX_UDP_PAYLOAD_LEN {
                    let payload_len = payload.len();
                    return Err(self.fail(TunnelError::PeerPayloadTooLarge { payload_len }));
                }
                self.stats.datagrams_received += 1;
                self.stats.payload_bytes_received += payload.len() as u64;
                Ok(Some(payload))
            }
        }
    }

    // -- MTU ---------------------------------------------------------------

    /// The outer connection's maximum datagram size as last reported.
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    /// The inner MTU: payload bytes that fit in one datagram right now
    /// (RFC 9298 §5).
    ///
    /// This is [`max_datagram_size`](Self::max_datagram_size) minus the two
    /// varint prefixes, so it changes when the outer path MTU changes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Revise the outer maximum datagram size and return the new inner MTU.
    ///
    /// The outer connection discovers its datagram limit over time, so this is
    /// the entry point for propagating that; [`TunnelTable::set_max_datagram_size`]
    /// applies it to every tunnel on a connection at once. A budget too small
    /// to hold the prefixes yields a capacity of `0`, which makes
    /// [`TunnelDriver::send_payload`] drop everything until there is room
    /// again — the RFC 9298 §5 discard, not an error.
    pub fn set_max_datagram_size(
        &mut self,
        max_datagram_size: usize,
    ) -> Result<usize, TunnelError> {
        self.capacity = tunnel_capacity(
            max_datagram_size,
            self.quarter_stream_id,
            CONTEXT_ID_UDP_PAYLOAD,
        )?;
        self.max_datagram_size = max_datagram_size;
        Ok(self.capacity)
    }

    // -- lifecycle and idleness --------------------------------------------

    /// Request a local close.
    ///
    /// Moves an active tunnel to [`TunnelState::Closing`];
    /// [`TunnelDriver::progress`] then returns [`TunnelAction::Closed`] once
    /// queued capsules are drained, at which point the caller finishes the
    /// request stream. A tunnel that already finished or failed is untouched.
    pub fn close(&mut self) {
        if matches!(self.state, TunnelState::Connecting | TunnelState::Open) {
            self.state = TunnelState::Closing;
        }
    }

    /// Record activity at `now`.
    ///
    /// The clock belongs to the caller: reading one here would be I/O, and it
    /// would also make idle behaviour untestable. Call this whenever a
    /// datagram or capsule moves in either direction; [`TunnelDriver::idle_for`]
    /// then answers the question an idle-timeout policy asks.
    pub fn touch(&mut self, now: Instant) {
        self.last_activity = Some(now);
    }

    /// The last instant passed to [`TunnelDriver::touch`], if any.
    pub fn last_activity(&self) -> Option<Instant> {
        self.last_activity
    }

    /// How long the tunnel has been idle as of `now`, or `None` if it has
    /// never been touched.
    pub fn idle_for(&self, now: Instant) -> Option<Duration> {
        self.last_activity
            .map(|last| now.saturating_duration_since(last))
    }

    // -- driving -----------------------------------------------------------

    /// Drive the tunnel forward; call in a loop after each feed.
    ///
    /// Outputs are prioritized: bytes to send, then readiness, then capsules,
    /// then closure, then [`TunnelAction::NeedData`]. A failed tunnel returns
    /// its original error forever, so a driver loop cannot spin past a
    /// protocol failure.
    pub fn progress(&mut self) -> Result<TunnelAction, TunnelError> {
        if let Some(err) = &self.failure {
            return Err(err.clone());
        }
        if !self.pending_stream_out.is_empty() {
            return Ok(TunnelAction::SendStream(std::mem::take(
                &mut self.pending_stream_out,
            )));
        }
        if self.ready_pending {
            self.ready_pending = false;
            return Ok(TunnelAction::Ready);
        }
        if let Some(capsule) = self.capsules.pop_front() {
            return Ok(TunnelAction::Capsule(capsule));
        }
        match self.state {
            TunnelState::Closing => {
                self.state = TunnelState::Closed;
                self.close_reported = true;
                Ok(TunnelAction::Closed)
            }
            TunnelState::Closed => {
                self.close_reported = true;
                Ok(TunnelAction::Closed)
            }
            _ => Ok(TunnelAction::NeedData),
        }
    }

    // -- internals ---------------------------------------------------------

    /// Reject any operation on an already-failed tunnel.
    fn check_live(&self) -> Result<(), TunnelError> {
        match &self.failure {
            Some(err) => Err(err.clone()),
            None => Ok(()),
        }
    }

    /// Record `error` as the terminal failure and return it unchanged.
    fn fail(&mut self, error: TunnelError) -> TunnelError {
        self.state = TunnelState::Failed;
        if self.failure.is_none() {
            self.failure = Some(error.clone());
        }
        error
    }
}

// ---------------------------------------------------------------------------
// TunnelTable
// ---------------------------------------------------------------------------

/// Where one received datagram belongs (RFC 9297 §2.1, RFC 9298 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch<'d> {
    /// Deliver these UDP payload bytes to the named tunnel.
    Deliver {
        /// The tunnel the datagram belongs to.
        quarter_stream_id: QuarterStreamId,
        /// The UDP payload, which may legitimately be empty.
        payload: &'d [u8],
    },
    /// No tunnel is registered under this Quarter Stream ID, so the datagram
    /// is dropped. This is ordinary after a tunnel closes, since datagrams
    /// already in flight keep arriving.
    UnknownTunnel {
        /// The unrecognized key.
        quarter_stream_id: QuarterStreamId,
    },
    /// The tunnel exists but the Context ID is not 0, so the datagram is
    /// dropped (RFC 9298 §5). Never an error.
    UnknownContext {
        /// The tunnel the datagram was addressed to.
        quarter_stream_id: QuarterStreamId,
        /// The Context ID that was not recognized.
        context_id: u64,
    },
}

/// The tunnels multiplexed over one outer HTTP/3 connection, keyed by Quarter
/// Stream ID (RFC 9297 §2.1).
///
/// `read_datagram` is connection-level, so something has to route. This table
/// is that something: [`TunnelTable::dispatch`] decodes a datagram once and
/// says which tunnel it belongs to, and
/// [`TunnelTable::set_max_datagram_size`] pushes a connection-wide MTU change
/// into every tunnel, since the outer datagram limit is a property of the
/// connection rather than of any one tunnel.
#[derive(Debug, Clone)]
pub struct TunnelTable {
    tunnels: HashMap<QuarterStreamId, TunnelDriver>,
    max_datagram_size: usize,
    unknown_tunnel_drops: u64,
}

impl TunnelTable {
    /// An empty table for a connection whose current maximum datagram size is
    /// `max_datagram_size`.
    pub fn new(max_datagram_size: usize) -> Self {
        Self {
            tunnels: HashMap::new(),
            max_datagram_size,
            unknown_tunnel_drops: 0,
        }
    }

    /// The connection's maximum datagram size as last reported.
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    /// Number of registered tunnels.
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Whether no tunnels are registered.
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// Datagrams dropped because no tunnel owned their Quarter Stream ID.
    pub fn unknown_tunnel_drops(&self) -> u64 {
        self.unknown_tunnel_drops
    }

    /// Register `tunnel` under its own Quarter Stream ID.
    ///
    /// The connection's current maximum datagram size is applied to it on the
    /// way in, so a tunnel created before the connection's limit was known
    /// picks up the right capacity. A key already in use yields
    /// [`TunnelError::DuplicateTunnel`] and the table is left unchanged —
    /// reusing a key would silently misroute another tunnel's datagrams.
    pub fn insert(&mut self, mut tunnel: TunnelDriver) -> Result<(), TunnelError> {
        let key = tunnel.quarter_stream_id();
        if self.tunnels.contains_key(&key) {
            return Err(TunnelError::DuplicateTunnel {
                quarter_stream_id: key,
            });
        }
        tunnel.set_max_datagram_size(self.max_datagram_size)?;
        self.tunnels.insert(key, tunnel);
        Ok(())
    }

    /// Look up a tunnel.
    pub fn get(&self, quarter_stream_id: QuarterStreamId) -> Option<&TunnelDriver> {
        self.tunnels.get(&quarter_stream_id)
    }

    /// Look up a tunnel for driving.
    pub fn get_mut(&mut self, quarter_stream_id: QuarterStreamId) -> Option<&mut TunnelDriver> {
        self.tunnels.get_mut(&quarter_stream_id)
    }

    /// Unregister a tunnel, returning it so the caller can read its final
    /// state and statistics.
    pub fn remove(&mut self, quarter_stream_id: QuarterStreamId) -> Option<TunnelDriver> {
        self.tunnels.remove(&quarter_stream_id)
    }

    /// Every registered Quarter Stream ID, in unspecified order.
    pub fn ids(&self) -> impl Iterator<Item = QuarterStreamId> + '_ {
        self.tunnels.keys().copied()
    }

    /// Every registered tunnel, in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &TunnelDriver> + '_ {
        self.tunnels.values()
    }

    /// Revise the connection's maximum datagram size and recompute every
    /// tunnel's inner MTU (RFC 9298 §5).
    pub fn set_max_datagram_size(&mut self, max_datagram_size: usize) -> Result<(), TunnelError> {
        for tunnel in self.tunnels.values_mut() {
            tunnel.set_max_datagram_size(max_datagram_size)?;
        }
        self.max_datagram_size = max_datagram_size;
        Ok(())
    }

    /// Route one datagram read off the outer connection (RFC 9297 §2.1).
    ///
    /// Decoding happens once, here, and the owning tunnel's counters are
    /// updated as a side effect. The two drop cases — no such tunnel, unknown
    /// Context ID — are returned as ordinary outcomes, not errors, since both
    /// are expected on a live connection. Framing damage returns
    /// [`TunnelError::Codec`], and the caller drops the datagram; a peer
    /// payload over [`MAX_UDP_PAYLOAD_LEN`] fails that one tunnel with
    /// [`TunnelError::PeerPayloadTooLarge`] and the caller must abort its
    /// stream.
    pub fn dispatch<'d>(&mut self, datagram: &'d [u8]) -> Result<Dispatch<'d>, TunnelError> {
        let decoded = decode_datagram(datagram)?;
        let key = decoded.quarter_stream_id();
        let Some(tunnel) = self.tunnels.get_mut(&key) else {
            self.unknown_tunnel_drops += 1;
            return Ok(Dispatch::UnknownTunnel {
                quarter_stream_id: key,
            });
        };
        match tunnel.accept_decoded(decoded)? {
            Some(payload) => Ok(Dispatch::Deliver {
                quarter_stream_id: key,
                payload,
            }),
            None => {
                let context_id = match decoded {
                    HttpDatagram::UnknownContext { context_id, .. } => context_id,
                    HttpDatagram::UdpPayload { .. } => CONTEXT_ID_UDP_PAYLOAD,
                };
                Ok(Dispatch::UnknownContext {
                    quarter_stream_id: key,
                    context_id,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{encode_datagram, encode_udp_payload};

    const MDS: usize = 1350;

    fn config() -> TunnelConfig {
        TunnelConfig::new("proxy.example.com:443", "example.org", 443).unwrap()
    }

    fn driver(id: u64) -> TunnelDriver {
        TunnelDriver::new(config(), QuarterStreamId::new(id), MDS).unwrap()
    }

    /// Start the tunnel and accept a well-formed response.
    fn opened(id: u64) -> TunnelDriver {
        let mut tunnel = driver(id);
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::Ready);
        tunnel
    }

    /// `type=0x1234, len=3, value=[1,2,3]` — a 0x1234 varint is two bytes.
    fn sample_capsule() -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(0x1234, &mut out).unwrap();
        encode_varint(3, &mut out).unwrap();
        out.extend_from_slice(&[1, 2, 3]);
        out
    }

    // -- request construction ---------------------------------------------

    #[test]
    fn start_builds_the_connect_udp_request() {
        let config = config()
            .with_auth(AuthHeader::proxy_authorization("Basic dXNlcjpwYXNz").unwrap())
            .with_header("x-route", "eu")
            .unwrap();
        let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();

        let request = tunnel.start().unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.protocol, "connect-udp");
        assert_eq!(request.scheme, "https");
        assert_eq!(request.authority, "proxy.example.com:443");
        assert_eq!(request.path, "/.well-known/masque/udp/example.org/443/");
        // RFC 9297 §3.4 goes out first, then auth, then extras.
        assert_eq!(
            request.headers,
            vec![
                ("capsule-protocol".to_string(), "?1".to_string()),
                (
                    "proxy-authorization".to_string(),
                    "Basic dXNlcjpwYXNz".to_string()
                ),
                ("x-route".to_string(), "eu".to_string()),
            ]
        );
        assert_eq!(request.header("capsule-protocol"), Some("?1"));
        assert_eq!(request.header("absent"), None);
    }

    #[test]
    fn ipv6_target_is_percent_encoded_in_the_path() {
        let config = TunnelConfig::new("proxy:443", "2001:db8::42", 443).unwrap();
        assert_eq!(
            config.path(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
    }

    #[test]
    fn invalid_target_is_rejected_before_any_request_exists() {
        // RFC 9298 §2: abort rather than send a request built from an invalid
        // template expansion.
        assert!(matches!(
            TunnelConfig::new("proxy:443", "example.org", 0),
            Err(TunnelError::Codec(CodecError::InvalidTargetPort {
                port: 0
            }))
        ));
        assert!(matches!(
            TunnelConfig::new("proxy:443", "", 443),
            Err(TunnelError::Codec(CodecError::EmptyTargetHost))
        ));
        assert!(matches!(
            TunnelConfig::new("", "example.org", 443),
            Err(TunnelError::EmptyProxyAuthority)
        ));
    }

    #[test]
    fn header_validation_rejects_uppercase_and_control_characters() {
        assert!(matches!(
            AuthHeader::new("Proxy-Authorization", "Basic x"),
            Err(TunnelError::InvalidHeaderName { .. })
        ));
        assert!(matches!(
            AuthHeader::new("proxy-authorization", "Basic \nx"),
            Err(TunnelError::InvalidHeaderValue { .. })
        ));
        assert!(matches!(
            AuthHeader::new("proxy-authorization", " Basic x"),
            Err(TunnelError::InvalidHeaderValue { .. })
        ));
        let auth = AuthHeader::authorization("Bearer t").unwrap();
        assert_eq!(auth.name(), "authorization");
        assert_eq!(auth.value(), "Bearer t");
    }

    #[test]
    fn start_twice_is_a_sequencing_error() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        assert!(matches!(
            tunnel.start(),
            Err(TunnelError::InvalidState {
                state: TunnelState::Connecting
            })
        ));
    }

    // -- response validation (RFC 9298 §3.5) -------------------------------

    #[test]
    fn successful_handshake_opens_the_tunnel() {
        let tunnel = opened(1);
        assert_eq!(tunnel.state(), TunnelState::Open);
        assert!(tunnel.is_open());
        assert!(tunnel.failure().is_none());
    }

    #[test]
    fn capsule_protocol_header_is_matched_case_insensitively_with_parameters() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        tunnel
            .feed_response(201, [("Capsule-Protocol", " ?1 ")])
            .unwrap();
        assert!(tunnel.is_open());
    }

    /// A 2xx that omits `capsule-protocol` opens the tunnel.
    ///
    /// This used to fail, and that was our bug, not the proxy's: RFC 9297 §3.4
    /// makes sending the header a SHOULD, and the requirements RFC 9298 §3.5
    /// imports (RFC 9297 §3.2) do not include it, because a 2xx answer to
    /// `connect-udp` already puts the Capsule Protocol in force through the
    /// upgrade token. Refusing such a proxy rejected a peer that was within
    /// the specification — and, through the route quarantine, blacklisted it.
    #[test]
    fn two_xx_without_capsule_protocol_opens_the_tunnel() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        tunnel.feed_response(200, [("server", "proxy")]).unwrap();
        assert!(tunnel.is_open());
        assert_eq!(
            tunnel.capsule_protocol_header(),
            CapsuleProtocolHeader::Absent,
            "the omission must be recorded so the caller can log it"
        );
    }

    /// `?0` has the same meaning as absent, in RFC 9297 §3.4's own words, so
    /// it gets the same treatment — open, and recorded as what was seen.
    #[test]
    fn capsule_protocol_false_opens_the_tunnel_and_is_recorded() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?0")])
            .unwrap();
        assert!(tunnel.is_open());
        assert_eq!(
            tunnel.capsule_protocol_header(),
            CapsuleProtocolHeader::NotTrue
        );
    }

    /// RFC 9297 §3.4 names this case: repeated occurrences make the field a
    /// List, which "MUST be handled as if the field were not present". The
    /// hazard is a loop that just keeps the last value — with `?0` then `?1`
    /// that silently reports a negotiation the field never expressed.
    #[test]
    fn a_repeated_capsule_protocol_field_is_reported_as_repeated() {
        for values in [["?0", "?1"], ["?1", "?0"], ["?1", "?1"]] {
            let mut tunnel = driver(1);
            tunnel.start().unwrap();
            tunnel
                .feed_response(
                    200,
                    [
                        ("capsule-protocol", values[0]),
                        ("capsule-protocol", values[1]),
                    ],
                )
                .unwrap();
            assert!(tunnel.is_open(), "{values:?}");
            assert_eq!(
                tunnel.capsule_protocol_header(),
                CapsuleProtocolHeader::Repeated,
                "{values:?} is a List, not a Boolean, whichever value came last"
            );
        }
    }

    /// RFC 9297 §3.2: 204, 205 and 206 "MUST NOT be sent on responses that use
    /// the Capsule Protocol", and a receiver seeing one "MUST treat the HTTP
    /// message as malformed". They are inside 2xx, so the status-range check
    /// alone let them through.
    #[test]
    fn a_204_205_or_206_response_is_malformed() {
        for status in [204_u16, 205, 206] {
            let mut tunnel = driver(1);
            tunnel.start().unwrap();
            let err = tunnel
                .feed_response(status, [("capsule-protocol", "?1")])
                .unwrap_err();
            assert_eq!(
                err,
                TunnelError::MalformedResponse {
                    reason: MalformedResponseReason::ForbiddenStatus { status }
                }
            );
            assert_eq!(tunnel.state(), TunnelState::Failed);
            // Poisoned: the driver loop keeps seeing the same failure.
            assert_eq!(tunnel.progress().unwrap_err(), err);
        }
    }

    /// RFC 9297 §3.2 forbids `content-length`, `content-type` and
    /// `transfer-encoding` on a Capsule Protocol message. `content-length: 0`
    /// on a bodyless 200 is the one that actually shows up, because HTTP
    /// frameworks add it; accepting it would leave us parsing an HTTP content
    /// stream as capsules and reporting the damage as capsule framing.
    #[test]
    fn a_response_carrying_a_forbidden_content_header_is_malformed() {
        for (name, value) in [
            ("content-length", "0"),
            ("Content-Length", "42"),
            ("content-type", "application/octet-stream"),
            ("transfer-encoding", "chunked"),
        ] {
            let mut tunnel = driver(1);
            tunnel.start().unwrap();
            let err = tunnel
                .feed_response(200, [("capsule-protocol", "?1"), (name, value)])
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    TunnelError::MalformedResponse {
                        reason: MalformedResponseReason::ForbiddenHeader { .. }
                    }
                ),
                "{name}: {err:?}"
            );
            assert_eq!(tunnel.state(), TunnelState::Failed);
            assert!(
                err.to_string().contains(&name.to_ascii_lowercase()),
                "the error must name the field it saw: {err}"
            );
        }
    }

    #[test]
    fn non_2xx_fails_even_with_capsule_protocol() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        let err = tunnel
            .feed_response(407, [("capsule-protocol", "?1")])
            .unwrap_err();
        assert_eq!(err, TunnelError::RejectedStatus { status: 407 });
        assert_eq!(tunnel.state(), TunnelState::Failed);
    }

    #[test]
    fn datagrams_are_refused_before_the_response() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        assert!(matches!(
            tunnel.send_payload(b"early"),
            Err(TunnelError::InvalidState {
                state: TunnelState::Connecting
            })
        ));
    }

    // -- incremental capsule parsing (RFC 9297 §3.2, §3.3) -----------------

    #[test]
    fn capsule_split_across_feeds_is_reassembled() {
        let mut tunnel = opened(1);
        let bytes = sample_capsule();

        // Byte at a time: nothing emerges until the last one lands.
        for byte in &bytes[..bytes.len() - 1] {
            tunnel.feed_stream(&[*byte]).unwrap();
            assert_eq!(tunnel.progress().unwrap(), TunnelAction::NeedData);
        }
        tunnel.feed_stream(&bytes[bytes.len() - 1..]).unwrap();

        assert_eq!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(OwnedCapsule {
                capsule_type: 0x1234,
                value: vec![1, 2, 3],
            })
        );
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::NeedData);
        assert_eq!(tunnel.stats().capsules_received, 1);
    }

    #[test]
    fn several_capsules_in_one_feed_are_all_queued() {
        let mut tunnel = opened(1);
        let mut bytes = sample_capsule();
        bytes.extend(sample_capsule());
        // Plus the head of a third, which must stay buffered.
        bytes.extend_from_slice(&[0x52]);

        tunnel.feed_stream(&bytes).unwrap();
        assert!(matches!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(_)
        ));
        assert!(matches!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(_)
        ));
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::NeedData);
        assert_eq!(tunnel.stats().capsules_received, 2);
    }

    #[test]
    fn unknown_capsule_types_are_reported_and_skipped_cleanly() {
        let mut tunnel = opened(1);
        // An unknown type followed by another capsule: the framing must be
        // skipped correctly or the second one would not parse (RFC 9297 §3.2).
        let mut bytes = Vec::new();
        encode_varint(0x3fff_ffff, &mut bytes).unwrap();
        encode_varint(2, &mut bytes).unwrap();
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        bytes.extend(sample_capsule());

        tunnel.feed_stream(&bytes).unwrap();
        assert_eq!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(OwnedCapsule {
                capsule_type: 0x3fff_ffff,
                value: vec![0xaa, 0xbb],
            })
        );
        assert_eq!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(OwnedCapsule {
                capsule_type: 0x1234,
                value: vec![1, 2, 3],
            })
        );
    }

    #[test]
    fn truncated_capsule_at_stream_end_is_malformed() {
        // RFC 9297 §3.3: a stream that ends mid-capsule is a malformed message.
        let mut tunnel = opened(1);
        let bytes = sample_capsule();
        tunnel.feed_stream(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::NeedData);

        let err = tunnel.feed_stream_end().unwrap_err();
        assert!(matches!(err, TunnelError::MalformedCapsule(_)));
        assert_eq!(tunnel.state(), TunnelState::Failed);
        assert_eq!(tunnel.progress().unwrap_err(), err);
        // Every later operation reports the same failure.
        assert_eq!(tunnel.feed_stream(&[0]).unwrap_err(), err);
        assert_eq!(tunnel.send_payload(b"x").unwrap_err(), err);
    }

    /// A capsule declaring more than the reassembly ceiling is stepped over,
    /// and the capsule after it is still delivered.
    ///
    /// This test asserted the opposite — that the tunnel died with a
    /// `CapsuleBufferOverflow` — and that was the wrong behaviour twice over.
    /// RFC 9297 §3.2 requires an unknown Capsule Type be "silently drop[ped]
    /// and skip[ped] over ... to parse the next Capsule", and RFC 9298 §5 asks
    /// that an over-large DATAGRAM capsule be discarded "without buffering the
    /// capsule contents". Failing instead reset the request stream, killed the
    /// inner QUIC connection and quarantined the route — over one capsule we
    /// had no use for.
    #[test]
    fn a_capsule_over_the_reassembly_limit_is_skipped_not_fatal() {
        let config = config().with_max_stream_buffer(16);
        let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();

        // An over-large capsule, delivered in pieces the way a QUIC stream
        // actually arrives, followed by a small one that must survive it.
        let mut oversized = Vec::new();
        encode_varint(0x1234, &mut oversized).unwrap();
        encode_varint(1_000, &mut oversized).unwrap();
        oversized.resize(oversized.len() + 1_000, 0xAA);

        let mut keeper = Vec::new();
        encode_varint(0x4242, &mut keeper).unwrap();
        encode_varint(3, &mut keeper).unwrap();
        keeper.extend_from_slice(b"abc");

        let mut stream = oversized;
        stream.extend_from_slice(&keeper);
        for chunk in stream.chunks(7) {
            tunnel
                .feed_stream(chunk)
                .expect("an over-large capsule must not end the tunnel");
        }

        assert!(tunnel.is_open());
        assert_eq!(tunnel.stats().capsules_skipped_over_limit, 1);
        assert_eq!(
            tunnel.stats().capsules_received,
            1,
            "only the capsule within the limit is delivered"
        );
        let delivered = loop {
            match tunnel.progress().unwrap() {
                TunnelAction::Capsule(capsule) => break capsule,
                TunnelAction::NeedData => panic!("the small capsule was not delivered"),
                _ => {}
            }
        };
        assert_eq!(delivered.capsule_type, 0x4242);
        assert_eq!(delivered.value, b"abc");
    }

    #[test]
    fn capsule_length_at_32_bit_limit_waits_for_remaining_bytes() {
        let config = config().with_max_stream_buffer(u32::MAX as usize);
        let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();
        let mut header = Vec::new();
        encode_varint(0x1234, &mut header).unwrap();
        encode_varint(u32::MAX as u64, &mut header).unwrap();
        tunnel.feed_stream(&header).unwrap();
        assert!(tunnel.is_open());
        assert_eq!(tunnel.stats().capsules_received, 0);
        assert!(matches!(
            tunnel.feed_stream_end(),
            Err(TunnelError::MalformedCapsule(_))
        ));
    }

    /// The same byte sequence must give the same result however the peer chops
    /// up its writes. The old check looked at leftover bytes rather than at the
    /// declared length, so one `feed_stream` call succeeded where several
    /// failed — a protocol outcome decided by TCP-level framing.
    #[test]
    fn skipping_does_not_depend_on_how_the_stream_is_chunked() {
        let mut stream = Vec::new();
        encode_varint(0x1234, &mut stream).unwrap();
        encode_varint(1_000, &mut stream).unwrap();
        stream.resize(stream.len() + 1_000, 0xAA);
        encode_varint(0x4242, &mut stream).unwrap();
        encode_varint(3, &mut stream).unwrap();
        stream.extend_from_slice(b"abc");

        for chunk_size in [1_usize, 3, 7, 64, 999, stream.len()] {
            let config = config().with_max_stream_buffer(16);
            let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();
            tunnel.start().unwrap();
            tunnel
                .feed_response(200, [("capsule-protocol", "?1")])
                .unwrap();
            for chunk in stream.chunks(chunk_size) {
                tunnel.feed_stream(chunk).expect("chunk size {chunk_size}");
            }
            assert!(tunnel.is_open(), "chunk size {chunk_size}");
            assert_eq!(
                (
                    tunnel.stats().capsules_skipped_over_limit,
                    tunnel.stats().capsules_received
                ),
                (1, 1),
                "chunk size {chunk_size} changed the outcome"
            );
        }
    }

    /// A stream that ends while an over-large capsule is still being skipped
    /// is a truncated capsule, and RFC 9297 §3.3 requires treating that as
    /// malformed. Declining to *deliver* a capsule is not declining to track
    /// the stream's framing.
    #[test]
    fn a_stream_ending_mid_skip_is_malformed() {
        let config = config().with_max_stream_buffer(16);
        let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();

        let mut bytes = Vec::new();
        encode_varint(0x1234, &mut bytes).unwrap();
        encode_varint(1_000, &mut bytes).unwrap();
        bytes.resize(bytes.len() + 10, 0xAA); // 990 bytes short
        tunnel.feed_stream(&bytes).unwrap();
        assert!(tunnel.is_open());

        let err = tunnel.feed_stream_end().unwrap_err();
        assert!(
            matches!(err, TunnelError::MalformedCapsule(_)),
            "got {err:?}"
        );
        assert_eq!(tunnel.state(), TunnelState::Failed);
    }

    /// The bound the ceiling exists for still holds: a capsule declaring more
    /// than can be addressed is skipped rather than reserved for, so a hostile
    /// length costs nothing.
    #[test]
    fn an_absurd_capsule_length_buffers_nothing() {
        let config = config().with_max_stream_buffer(16);
        let mut tunnel = TunnelDriver::new(config, QuarterStreamId::new(1), MDS).unwrap();
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();

        let mut bytes = Vec::new();
        encode_varint(0x1234, &mut bytes).unwrap();
        encode_varint(crate::codec::VARINT_MAX, &mut bytes).unwrap();
        bytes.resize(bytes.len() + 32, 0);

        tunnel
            .feed_stream(&bytes)
            .expect("a 2^62-1 length is skipped, not buffered");
        assert!(tunnel.is_open());
        assert_eq!(tunnel.stats().capsules_skipped_over_limit, 1);
    }

    #[test]
    fn stream_bytes_before_the_response_are_a_sequencing_error() {
        let mut tunnel = driver(1);
        tunnel.start().unwrap();
        assert!(matches!(
            tunnel.feed_stream(&sample_capsule()),
            Err(TunnelError::InvalidState {
                state: TunnelState::Connecting
            })
        ));
    }

    #[test]
    fn queued_capsules_come_back_as_stream_bytes() {
        let mut tunnel = opened(1);
        tunnel.queue_capsule(0x1234, &[1, 2, 3]).unwrap();
        assert_eq!(
            tunnel.progress().unwrap(),
            TunnelAction::SendStream(sample_capsule())
        );
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::NeedData);
    }

    // -- datagrams and the two size limits (RFC 9298 §5) -------------------

    #[test]
    fn payloads_round_trip_through_the_tunnel() {
        let mut tunnel = opened(7);
        let outcome = tunnel.send_payload(b"inner quic packet").unwrap();
        let datagram = outcome.datagram().unwrap().to_vec();
        assert_eq!(
            datagram,
            encode_udp_payload(QuarterStreamId::new(7), b"inner quic packet").unwrap()
        );

        assert_eq!(
            tunnel.accept_datagram(&datagram).unwrap(),
            Some(&b"inner quic packet"[..])
        );
        let stats = tunnel.stats();
        assert_eq!(stats.datagrams_sent, 1);
        assert_eq!(stats.datagrams_received, 1);
        assert_eq!(stats.payload_bytes_sent, 17);
        assert_eq!(stats.payload_bytes_received, 17);
    }

    #[test]
    fn over_protocol_max_is_fatal_on_receive_and_refused_on_send() {
        let mut tunnel = opened(1);

        // Send side: MUST NOT send, but nothing reached the wire so the tunnel
        // survives.
        let huge = vec![0u8; MAX_UDP_PAYLOAD_LEN + 1];
        assert_eq!(
            tunnel.send_payload(&huge).unwrap_err(),
            TunnelError::PayloadTooLarge {
                payload_len: MAX_UDP_PAYLOAD_LEN + 1
            }
        );
        assert_eq!(tunnel.state(), TunnelState::Open);

        // Receive side: MUST abort the request stream, so the tunnel fails.
        let datagram = encode_udp_payload(QuarterStreamId::new(1), &huge).unwrap();
        let err = tunnel.accept_datagram(&datagram).unwrap_err();
        assert_eq!(
            err,
            TunnelError::PeerPayloadTooLarge {
                payload_len: MAX_UDP_PAYLOAD_LEN + 1
            }
        );
        assert_eq!(tunnel.state(), TunnelState::Failed);
    }

    #[test]
    fn over_capacity_is_a_counted_drop_not_an_error() {
        let mut tunnel = opened(1);
        let capacity = tunnel.capacity();
        let payload = vec![0u8; capacity + 1];
        assert_eq!(
            tunnel.send_payload(&payload).unwrap(),
            SendOutcome::Dropped {
                payload_len: capacity + 1,
                capacity,
            }
        );
        assert_eq!(tunnel.stats().dropped_over_capacity, 1);
        assert_eq!(tunnel.stats().datagrams_sent, 0);
        assert_eq!(tunnel.state(), TunnelState::Open);
    }

    #[test]
    fn unknown_context_is_dropped_without_error() {
        let mut tunnel = opened(1);
        let datagram = encode_datagram(QuarterStreamId::new(1), 9, b"opaque").unwrap();
        assert_eq!(tunnel.accept_datagram(&datagram).unwrap(), None);
        assert_eq!(tunnel.stats().dropped_unknown_context, 1);
        assert_eq!(tunnel.state(), TunnelState::Open);
    }

    #[test]
    fn a_datagram_for_another_tunnel_is_refused() {
        let mut tunnel = opened(1);
        let datagram = encode_udp_payload(QuarterStreamId::new(2), b"x").unwrap();
        assert_eq!(
            tunnel.accept_datagram(&datagram).unwrap_err(),
            TunnelError::WrongTunnel {
                expected: QuarterStreamId::new(1),
                actual: QuarterStreamId::new(2),
            }
        );
    }

    // -- MTU accounting ----------------------------------------------------

    #[test]
    fn capacity_tracks_the_outer_datagram_size() {
        let mut tunnel = opened(1);
        // Quarter stream 1 and context 0 are one varint byte each.
        assert_eq!(tunnel.capacity(), MDS - 2);

        assert_eq!(tunnel.set_max_datagram_size(1200).unwrap(), 1198);
        assert_eq!(tunnel.capacity(), 1198);
        assert_eq!(tunnel.max_datagram_size(), 1200);

        // Too small to hold even the prefixes: capacity 0, so everything is
        // dropped rather than erroring.
        assert_eq!(tunnel.set_max_datagram_size(1).unwrap(), 0);
        assert!(matches!(
            tunnel.send_payload(b"x").unwrap(),
            SendOutcome::Dropped { capacity: 0, .. }
        ));

        // A large Quarter Stream ID costs more prefix bytes.
        let wide = opened(1_000_000);
        assert_eq!(wide.capacity(), MDS - 5);
    }

    #[test]
    fn capacity_is_capped_at_the_protocol_maximum() {
        let mut tunnel = opened(1);
        tunnel.set_max_datagram_size(1_000_000).unwrap();
        assert_eq!(tunnel.capacity(), MAX_UDP_PAYLOAD_LEN);
    }

    // -- lifecycle ---------------------------------------------------------

    #[test]
    fn lifecycle_runs_connecting_open_closing_closed() {
        let mut tunnel = driver(1);
        assert_eq!(tunnel.state(), TunnelState::Connecting);
        tunnel.start().unwrap();
        tunnel
            .feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();
        assert_eq!(tunnel.state(), TunnelState::Open);

        tunnel.close();
        assert_eq!(tunnel.state(), TunnelState::Closing);
        // Ready is still owed from the response, then the close is reported.
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::Ready);
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::Closed);
        assert_eq!(tunnel.state(), TunnelState::Closed);
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::Closed);

        // Closed tunnels do not reopen and do not carry datagrams.
        tunnel.close();
        assert_eq!(tunnel.state(), TunnelState::Closed);
        assert!(matches!(
            tunnel.send_payload(b"x"),
            Err(TunnelError::InvalidState {
                state: TunnelState::Closed
            })
        ));
    }

    #[test]
    fn queued_capsules_are_drained_before_the_close_is_reported() {
        let mut tunnel = opened(1);
        tunnel.feed_stream(&sample_capsule()).unwrap();
        tunnel.feed_stream_end().unwrap();
        assert_eq!(tunnel.state(), TunnelState::Closed);
        assert!(matches!(
            tunnel.progress().unwrap(),
            TunnelAction::Capsule(_)
        ));
        assert_eq!(tunnel.progress().unwrap(), TunnelAction::Closed);
    }

    #[test]
    fn idleness_is_measured_with_caller_supplied_time() {
        let mut tunnel = opened(1);
        assert_eq!(tunnel.last_activity(), None);
        assert_eq!(tunnel.idle_for(Instant::now()), None);

        let t0 = Instant::now();
        tunnel.touch(t0);
        assert_eq!(tunnel.last_activity(), Some(t0));
        assert_eq!(
            tunnel.idle_for(t0 + Duration::from_secs(30)),
            Some(Duration::from_secs(30))
        );
        // Time going backwards saturates rather than panicking.
        assert_eq!(
            tunnel.idle_for(t0 - Duration::from_secs(5)),
            Some(Duration::ZERO)
        );
    }

    // -- tunnel table ------------------------------------------------------

    #[test]
    fn table_registers_finds_and_unregisters() {
        let mut table = TunnelTable::new(MDS);
        assert!(table.is_empty());

        table.insert(opened(1)).unwrap();
        table.insert(opened(2)).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.get(QuarterStreamId::new(1)).is_some());
        assert!(table.get_mut(QuarterStreamId::new(2)).is_some());
        assert!(table.get(QuarterStreamId::new(3)).is_none());

        let mut ids: Vec<u64> = table.ids().map(QuarterStreamId::value).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
        assert_eq!(table.iter().count(), 2);

        assert!(matches!(
            table.insert(opened(1)),
            Err(TunnelError::DuplicateTunnel { .. })
        ));
        assert_eq!(table.len(), 2);

        let removed = table.remove(QuarterStreamId::new(1)).unwrap();
        assert_eq!(removed.quarter_stream_id(), QuarterStreamId::new(1));
        assert_eq!(table.len(), 1);
        assert!(table.remove(QuarterStreamId::new(1)).is_none());
    }

    #[test]
    fn table_demultiplexes_datagrams_between_tunnels() {
        let mut table = TunnelTable::new(MDS);
        table.insert(opened(1)).unwrap();
        table.insert(opened(2)).unwrap();

        let one = encode_udp_payload(QuarterStreamId::new(1), b"for-one").unwrap();
        assert_eq!(
            table.dispatch(&one).unwrap(),
            Dispatch::Deliver {
                quarter_stream_id: QuarterStreamId::new(1),
                payload: b"for-one",
            }
        );
        let two = encode_udp_payload(QuarterStreamId::new(2), b"for-two").unwrap();
        assert_eq!(
            table.dispatch(&two).unwrap(),
            Dispatch::Deliver {
                quarter_stream_id: QuarterStreamId::new(2),
                payload: b"for-two",
            }
        );

        // Only the addressed tunnel's counters moved.
        assert_eq!(
            table
                .get(QuarterStreamId::new(1))
                .unwrap()
                .stats()
                .datagrams_received,
            1
        );

        // A closed tunnel's late datagrams are dropped, not errors.
        let stray = encode_udp_payload(QuarterStreamId::new(9), b"late").unwrap();
        assert_eq!(
            table.dispatch(&stray).unwrap(),
            Dispatch::UnknownTunnel {
                quarter_stream_id: QuarterStreamId::new(9)
            }
        );
        assert_eq!(table.unknown_tunnel_drops(), 1);

        // Unknown Context ID: dropped and counted on the owning tunnel.
        let odd = encode_datagram(QuarterStreamId::new(2), 5, b"opaque").unwrap();
        assert_eq!(
            table.dispatch(&odd).unwrap(),
            Dispatch::UnknownContext {
                quarter_stream_id: QuarterStreamId::new(2),
                context_id: 5,
            }
        );
        assert_eq!(
            table
                .get(QuarterStreamId::new(2))
                .unwrap()
                .stats()
                .dropped_unknown_context,
            1
        );

        // Framing damage: an empty datagram has no Quarter Stream ID at all.
        assert!(matches!(
            table.dispatch(&[]),
            Err(TunnelError::Codec(CodecError::Truncated { .. }))
        ));
    }

    #[test]
    fn table_pushes_mtu_changes_into_every_tunnel() {
        let mut table = TunnelTable::new(MDS);
        table.insert(opened(1)).unwrap();
        table.insert(opened(2)).unwrap();

        table.set_max_datagram_size(900).unwrap();
        assert_eq!(table.max_datagram_size(), 900);
        for tunnel in table.iter() {
            assert_eq!(tunnel.capacity(), 898);
        }

        // A tunnel built with a stale size picks up the table's on insert.
        let mut late = TunnelDriver::new(config(), QuarterStreamId::new(3), 9999).unwrap();
        late.start().unwrap();
        late.feed_response(200, [("capsule-protocol", "?1")])
            .unwrap();
        table.insert(late).unwrap();
        assert_eq!(table.get(QuarterStreamId::new(3)).unwrap().capacity(), 898);
    }
}
