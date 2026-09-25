//! Wire codec for MASQUE CONNECT-UDP.
//!
//! This module is deliberately side-effect free: every function takes bytes (or
//! plain scalars) and returns bytes or a [`CodecError`]. No I/O, no sockets, no
//! HTTP. It covers four pieces of the protocol:
//!
//! 1. QUIC variable-length integers (RFC 9000 §16), the primitive every other
//!    field is built from;
//! 2. the two-layer HTTP Datagram payload
//!    `[quarter stream ID][context ID][payload]` (RFC 9297 §2.1, RFC 9298 §4);
//! 3. a minimal Capsule framing parser (RFC 9297 §3.2, §3.3) that reads the
//!    type/length frame and lets the caller skip unknown types;
//! 4. the CONNECT-UDP URI template expansion (RFC 9298 §3) and the two payload
//!    size limits of RFC 9298 §5.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A MASQUE encoding or decoding failure.
///
/// Every variant means "the input is malformed" or "the caller asked for
/// something unrepresentable". A non-zero Context ID is *not* an error and is
/// therefore not represented here — see [`HttpDatagram::UnknownContext`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// The input ended in the middle of a field.
    ///
    /// For Capsules this is RFC 9297 §3.3's "the stream ended before the
    /// capsule was complete", which the caller must treat as a malformed
    /// message.
    #[error("truncated {field}: {needed} more byte(s) needed")]
    Truncated {
        /// Name of the field that ran off the end of the input.
        field: &'static str,
        /// How many further bytes the field needed.
        needed: usize,
    },

    /// A value cannot be encoded as a QUIC varint (RFC 9000 §16 caps them at
    /// `2^62 - 1`, see [`VARINT_MAX`]).
    #[error("value {0} does not fit a QUIC varint (max {VARINT_MAX})")]
    VarintOutOfRange(u64),

    /// A Capsule Length does not fit in `usize` on this platform, so the
    /// capsule can never be satisfied by an in-memory buffer (RFC 9297 §3.3
    /// treats this as a malformed message).
    #[error("capsule type {capsule_type:#x} declares length {length}, which exceeds usize")]
    CapsuleLengthOverflow {
        /// The Capsule Type field that carried the unusable length.
        capsule_type: u64,
        /// The declared Capsule Length.
        length: u64,
    },

    /// A stream ID was not a client-initiated bidirectional stream, so it has
    /// no Quarter Stream ID (RFC 9297 §2.1).
    #[error("stream id {stream_id} is not a client-initiated bidirectional stream")]
    NotARequestStream {
        /// The offending stream ID.
        stream_id: u64,
    },

    /// `target_host` was empty after removing IPv6 literal brackets
    /// (RFC 9298 §3 requires a non-empty host).
    #[error("CONNECT-UDP target host must not be empty")]
    EmptyTargetHost,

    /// `target_port` was outside 1–65535 (RFC 9298 §3).
    #[error("CONNECT-UDP target port {port} is outside 1-65535")]
    InvalidTargetPort {
        /// The rejected port value.
        port: u16,
    },
}

// ---------------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 §16)
// ---------------------------------------------------------------------------

/// Largest value a QUIC variable-length integer can carry, `2^62 - 1`
/// (RFC 9000 §16).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Number of bytes [`encode_varint`] will emit for `value` (RFC 9000 §16).
///
/// Returns [`CodecError::VarintOutOfRange`] for values above [`VARINT_MAX`].
/// This is the function to use when budgeting datagram overhead against a
/// path MTU.
pub fn varint_len(value: u64) -> Result<usize, CodecError> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=VARINT_MAX => Ok(8),
        _ => Err(CodecError::VarintOutOfRange(value)),
    }
}

/// Append `value` to `out` as a QUIC variable-length integer (RFC 9000 §16).
///
/// The minimal encoding is always chosen. Values above [`VARINT_MAX`] are
/// rejected rather than panicking or silently truncating.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match varint_len(value)? {
        1 => out.push(value as u8),
        2 => out.extend_from_slice(&(0x4000_u16 | value as u16).to_be_bytes()),
        4 => out.extend_from_slice(&(0x8000_0000_u32 | value as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xC000_0000_0000_0000_u64 | value).to_be_bytes()),
    }
    Ok(())
}

/// Read a QUIC variable-length integer from `input` at `*pos`, advancing `*pos`
/// past it (RFC 9000 §16).
///
/// Non-minimal encodings are accepted, as RFC 9000 §16 explicitly permits them.
/// A field that runs past the end of `input` yields
/// [`CodecError::Truncated`].
pub fn decode_varint(input: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    let first = *input.get(*pos).ok_or(CodecError::Truncated {
        field: "varint",
        needed: 1,
    })?;
    // The two most significant bits encode log2 of the length.
    let len = 1_usize << (first >> 6);
    let available = input.len() - *pos;
    if available < len {
        return Err(CodecError::Truncated {
            field: "varint",
            needed: len - available,
        });
    }

    let mut value = u64::from(first & 0x3f);
    for &byte in &input[*pos + 1..*pos + len] {
        value = (value << 8) | u64::from(byte);
    }
    *pos += len;
    Ok(value)
}

// ---------------------------------------------------------------------------
// HTTP Datagram payload (RFC 9297 §2.1, RFC 9298 §4)
// ---------------------------------------------------------------------------

/// Context ID reserved for uncompressed UDP payloads (RFC 9298 §4).
pub const CONTEXT_ID_UDP_PAYLOAD: u64 = 0;

/// Theoretical maximum length of a UDP payload, `65535 - 8` (RFC 9298 §5).
///
/// A sender MUST NOT send a longer payload; a receiver MUST abort the request
/// stream if it gets one. See [`classify_payload`].
pub const MAX_UDP_PAYLOAD_LEN: usize = 65_527;

/// The Quarter Stream ID of a request stream: the stream ID divided by four
/// (RFC 9297 §2.1).
///
/// This is a newtype rather than a bare `u64` because the two units are
/// indistinguishable at a glance and trivially swapped. Getting it wrong is not
/// loud: quarter ID `0` happens to equal stream ID `0`, so the *first* tunnel on
/// a connection works either way and only the second one misbehaves. The
/// constructor you pick states which unit you hold —
/// [`QuarterStreamId::new`] for a value that is already quartered,
/// [`QuarterStreamId::from_request_stream_id`] for a raw stream ID.
///
/// `Hash` is derived so this can key a tunnel demultiplexing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuarterStreamId(u64);

impl QuarterStreamId {
    /// Wrap a value that is **already** a Quarter Stream ID (RFC 9297 §2.1).
    ///
    /// No division happens here.
    ///
    /// # Which constructor for `h3`'s `RequestStream::id()`
    ///
    /// In this repository, `h3::client::RequestStream::id().into_inner()`
    /// returns the raw QUIC stream ID. Pass it to
    /// [`QuarterStreamId::from_request_stream_id`] instead; `new` is for values
    /// that have already been divided by four.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Derive the Quarter Stream ID from a **raw** request stream ID
    /// (RFC 9297 §2.1).
    ///
    /// Request streams are client-initiated bidirectional streams, so their IDs
    /// are always multiples of four; anything else yields
    /// [`CodecError::NotARequestStream`] rather than silently truncating.
    ///
    /// Use this for `h3`'s `RequestStream::id()` in this repository, which
    /// reports the raw QUIC stream ID.
    pub fn from_request_stream_id(raw: u64) -> Result<Self, CodecError> {
        if !raw.is_multiple_of(4) {
            return Err(CodecError::NotARequestStream { stream_id: raw });
        }
        Ok(Self(raw / 4))
    }

    /// The Quarter Stream ID as a plain integer, i.e. what goes on the wire.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Alias for [`QuarterStreamId::value`], for callers that prefer the
    /// conventional newtype spelling.
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Recover the raw request stream ID this refers to (RFC 9297 §2.1), the
    /// inverse of [`QuarterStreamId::from_request_stream_id`].
    ///
    /// Values above [`VARINT_MAX`] could never have appeared on the wire and
    /// are rejected with [`CodecError::VarintOutOfRange`].
    pub fn request_stream_id(self) -> Result<u64, CodecError> {
        if self.0 > VARINT_MAX {
            return Err(CodecError::VarintOutOfRange(self.0));
        }
        Ok(self.0 * 4)
    }
}

/// Bytes the two varint prefixes occupy for a given stream and context
/// (RFC 9297 §2.1, RFC 9298 §4).
///
/// Subtract this from the outer connection's maximum datagram size to get the
/// usable inner MTU; [`tunnel_capacity`] does exactly that.
pub fn datagram_header_len(
    quarter_stream_id: QuarterStreamId,
    context_id: u64,
) -> Result<usize, CodecError> {
    Ok(varint_len(quarter_stream_id.value())? + varint_len(context_id)?)
}

/// Encode `[quarter stream ID][context ID][payload]` into `out`
/// (RFC 9297 §2.1, RFC 9298 §4).
///
/// `out` is appended to, not cleared. This function does **not** enforce the
/// 65527-byte limit — call [`classify_payload`] first, because the two
/// over-limit cases need different handling (abort vs. drop).
pub fn encode_datagram_into(
    quarter_stream_id: QuarterStreamId,
    context_id: u64,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    encode_varint(quarter_stream_id.value(), out)?;
    encode_varint(context_id, out)?;
    out.extend_from_slice(payload);
    Ok(())
}

/// Allocating form of [`encode_datagram_into`].
pub fn encode_datagram(
    quarter_stream_id: QuarterStreamId,
    context_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let mut out =
        Vec::with_capacity(datagram_header_len(quarter_stream_id, context_id)? + payload.len());
    encode_datagram_into(quarter_stream_id, context_id, payload, &mut out)?;
    Ok(out)
}

/// Encode an uncompressed UDP payload, i.e. [`encode_datagram`] with Context ID
/// [`CONTEXT_ID_UDP_PAYLOAD`] (RFC 9298 §4).
pub fn encode_udp_payload(
    quarter_stream_id: QuarterStreamId,
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    encode_datagram(quarter_stream_id, CONTEXT_ID_UDP_PAYLOAD, payload)
}

/// A successfully framed HTTP Datagram payload.
///
/// The split between the two variants is the point of this type: RFC 9298 §5
/// says a receiver that does not know a Context ID SHALL drop the datagram (or
/// buffer it briefly) and MUST NOT treat it as an error, so an unknown context
/// is a normal decode result and only real framing damage is a
/// [`CodecError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpDatagram<'a> {
    /// Context ID 0: an uncompressed UDP payload (RFC 9298 §4).
    UdpPayload {
        /// Quarter Stream ID the datagram belongs to (RFC 9297 §2.1).
        quarter_stream_id: QuarterStreamId,
        /// The UDP payload, which may legitimately be empty.
        payload: &'a [u8],
    },
    /// A non-zero Context ID. No context is ever registered by this client, so
    /// the caller drops the datagram and bumps a counter (RFC 9298 §5).
    UnknownContext {
        /// Quarter Stream ID the datagram belongs to (RFC 9297 §2.1).
        quarter_stream_id: QuarterStreamId,
        /// The Context ID that was not recognized.
        context_id: u64,
    },
}

impl HttpDatagram<'_> {
    /// Quarter Stream ID carried by either variant (RFC 9297 §2.1).
    ///
    /// This is the key a receiver routes on: match it against the
    /// [`QuarterStreamId`] of each open tunnel.
    pub fn quarter_stream_id(&self) -> QuarterStreamId {
        match *self {
            HttpDatagram::UdpPayload {
                quarter_stream_id, ..
            }
            | HttpDatagram::UnknownContext {
                quarter_stream_id, ..
            } => quarter_stream_id,
        }
    }

    /// The UDP payload, or `None` when the datagram must be dropped because its
    /// Context ID is unknown (RFC 9298 §5).
    pub fn udp_payload(&self) -> Option<&[u8]> {
        match *self {
            HttpDatagram::UdpPayload { payload, .. } => Some(payload),
            HttpDatagram::UnknownContext { .. } => None,
        }
    }
}

/// Decode an HTTP Datagram payload (RFC 9297 §2.1, RFC 9298 §4).
///
/// `input` is the datagram payload as delivered by QUIC, i.e. without the
/// QUIC DATAGRAM frame header. Returns [`HttpDatagram::UnknownContext`] for a
/// non-zero Context ID — that is a drop, not a failure — and a [`CodecError`]
/// only when the two varint prefixes are themselves damaged or truncated.
pub fn decode_datagram(input: &[u8]) -> Result<HttpDatagram<'_>, CodecError> {
    let mut pos = 0_usize;
    // Already a quarter value on the wire; no division.
    let quarter_stream_id = QuarterStreamId::new(decode_varint(input, &mut pos)?);
    let context_id = decode_varint(input, &mut pos)?;

    if context_id == CONTEXT_ID_UDP_PAYLOAD {
        Ok(HttpDatagram::UdpPayload {
            quarter_stream_id,
            payload: &input[pos..],
        })
    } else {
        Ok(HttpDatagram::UnknownContext {
            quarter_stream_id,
            context_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Capsule framing (RFC 9297 §3.2, §3.3)
// ---------------------------------------------------------------------------

/// One capsule: a type and its still-uninterpreted value (RFC 9297 §3.2).
///
/// No capsule type semantics are implemented here. Parsing the frame is enough
/// to satisfy RFC 9297 §3.2's "skip over unknown capsule types and continue
/// with the next capsule".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capsule<'a> {
    /// Capsule Type field (RFC 9297 §3.2).
    pub capsule_type: u64,
    /// Capsule Value field, exactly `Capsule Length` bytes long.
    pub value: &'a [u8],
}

/// A capsule's Type and Length, read without its Value
/// (RFC 9297 §3.2, Figure 3).
///
/// Produced by [`CapsuleParser::peek_header`]. `length` stays a `u64` on
/// purpose: the field is a QUIC varint and so may legally declare up to
/// 2^62-1, far past anything addressable, and the point of looking at the
/// header first is to make that decision *before* narrowing to `usize` or
/// reserving memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleHeader {
    /// Capsule Type field.
    pub capsule_type: u64,
    /// Capsule Length field: the declared length of the Value, in bytes.
    pub length: u64,
    /// Bytes the two header varints themselves occupy, which is what a caller
    /// skipping this capsule has to step over before the Value.
    pub header_len: usize,
}

/// Sequential reader over a complete capsule stream (RFC 9297 §3.2).
///
/// The parser treats its input as the *whole* capsule stream: a capsule whose
/// declared length runs past the end of the buffer is a truncation error, which
/// is RFC 9297 §3.3's "malformed message". A caller reading incrementally
/// should therefore buffer bytes until the request stream ends (or until it has
/// whole capsules) before handing them over.
///
/// Once a capsule fails to parse the reader is poisoned and keeps returning the
/// same error, so a caller cannot accidentally resynchronize onto payload bytes.
#[derive(Debug, Clone)]
pub struct CapsuleParser<'a> {
    input: &'a [u8],
    pos: usize,
    failed: Option<CodecError>,
}

impl<'a> CapsuleParser<'a> {
    /// Start reading capsules from `input` (RFC 9297 §3.2).
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            failed: None,
        }
    }

    /// Byte offset of the next unread capsule.
    pub fn offset(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed by [`CapsuleParser::next_capsule`].
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Read the next capsule.
    ///
    /// Returns `Ok(None)` once the input is exactly exhausted, `Ok(Some(..))`
    /// for every capsule — known or unknown, the caller just ignores the types
    /// it does not handle — and `Err` when the type/length frame is damaged or
    /// the value is truncated, which RFC 9297 §3.3 requires be treated as a
    /// malformed message.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule<'a>>, CodecError> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        if self.pos >= self.input.len() {
            return Ok(None);
        }

        match self.parse_one() {
            Ok(capsule) => Ok(Some(capsule)),
            Err(err) => {
                self.failed = Some(err.clone());
                Err(err)
            }
        }
    }

    /// Read the next capsule's Type and Length without needing its Value
    /// (RFC 9297 §3.2).
    ///
    /// Returns `Ok(None)` when the input is exactly exhausted, and
    /// [`CodecError::Truncated`] when the two header varints are themselves
    /// incomplete — the same "need more data" signal
    /// [`CapsuleParser::next_capsule`] gives, and not a failure.
    ///
    /// This exists so a caller can decide what to do with a capsule *before*
    /// committing memory to its Value. RFC 9297 §3.2 warns against
    /// accumulating the whole Value ("This approach SHOULD be avoided because
    /// it can consume flow control in underlying layers"), and RFC 9298 §5
    /// asks a receiver that will discard an over-large DATAGRAM capsule to
    /// "discard that capsule without buffering the capsule contents". Both
    /// need the length before the bytes.
    ///
    /// Unlike `next_capsule`, this does **not** advance the parser and does
    /// not poison it on truncation: it is a look, not a read.
    pub fn peek_header(&self) -> Result<Option<CapsuleHeader>, CodecError> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        let mut pos = self.pos;
        let capsule_type = decode_varint(self.input, &mut pos)?;
        let length = decode_varint(self.input, &mut pos)?;
        Ok(Some(CapsuleHeader {
            capsule_type,
            length,
            header_len: pos - self.pos,
        }))
    }

    fn parse_one(&mut self) -> Result<Capsule<'a>, CodecError> {
        let mut pos = self.pos;
        let capsule_type = decode_varint(self.input, &mut pos)?;
        let length = decode_varint(self.input, &mut pos)?;

        let length = usize::try_from(length).map_err(|_| CodecError::CapsuleLengthOverflow {
            capsule_type,
            length,
        })?;
        let available = self.input.len() - pos;
        if available < length {
            return Err(CodecError::Truncated {
                field: "capsule value",
                needed: length - available,
            });
        }

        let value = &self.input[pos..pos + length];
        self.pos = pos + length;
        Ok(Capsule {
            capsule_type,
            value,
        })
    }
}

/// Parse a complete capsule stream into a vector (RFC 9297 §3.2).
///
/// Convenience wrapper over [`CapsuleParser`] with the same truncation rules.
pub fn parse_capsules(input: &[u8]) -> Result<Vec<Capsule<'_>>, CodecError> {
    let mut parser = CapsuleParser::new(input);
    let mut out = Vec::new();
    while let Some(capsule) = parser.next_capsule()? {
        out.push(capsule);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// URI template (RFC 9298 §3)
// ---------------------------------------------------------------------------

/// The URI Template this client expands, as written in RFC 9298 §3.
pub const CONNECT_UDP_URI_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Percent-encode one URI Template variable using RFC 6570 simple string
/// expansion: everything outside RFC 3986 `unreserved` is escaped.
///
/// This is what forces `:` to `%3A` inside IPv6 literals, as RFC 9298 §3
/// requires.
fn percent_encode_variable(value: &str, out: &mut String) {
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
                out.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
            }
        }
    }
}

/// Expand [`CONNECT_UDP_URI_TEMPLATE`] into the `:path` of a CONNECT-UDP
/// request (RFC 9298 §3).
///
/// Validation, all of it mandatory per RFC 9298 §2/§3 — a template that cannot
/// be expanded means the request MUST NOT be sent:
///
/// - `target_host` must be non-empty;
/// - `target_port` must be in 1–65535, so only `0` can be rejected here since
///   the upper bound is already enforced by `u16`;
/// - the host is percent-encoded with RFC 6570 simple string expansion, which
///   escapes the colons of an IPv6 literal (`2001:db8::42` becomes
///   `2001%3Adb8%3A%3A42`) as well as any other character outside RFC 3986
///   `unreserved`.
///
/// A bracketed IPv6 literal (`[2001:db8::42]`, the form that appears in a URL
/// authority) has its brackets stripped first, since the brackets are authority
/// syntax and are not part of the host.
///
/// # Examples
///
/// ```
/// use lkmasque::codec::build_connect_udp_path;
///
/// assert_eq!(
///     build_connect_udp_path("example.com", 443).unwrap(),
///     "/.well-known/masque/udp/example.com/443/"
/// );
/// assert_eq!(
///     build_connect_udp_path("[2001:db8::42]", 443).unwrap(),
///     "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
/// );
/// ```
pub fn build_connect_udp_path(target_host: &str, target_port: u16) -> Result<String, CodecError> {
    let host = target_host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(target_host);

    if host.is_empty() {
        return Err(CodecError::EmptyTargetHost);
    }
    if target_port == 0 {
        return Err(CodecError::InvalidTargetPort { port: target_port });
    }

    let mut path = String::with_capacity(32 + host.len());
    path.push_str("/.well-known/masque/udp/");
    percent_encode_variable(host, &mut path);
    path.push('/');
    // A port is digits only, so it needs no escaping.
    let _ = write!(path, "{target_port}");
    path.push('/');
    Ok(path)
}

// ---------------------------------------------------------------------------
// Payload size limits (RFC 9298 §5)
// ---------------------------------------------------------------------------

/// What to do with a UDP payload of a given size (RFC 9298 §5).
///
/// The two over-limit cases are deliberately distinct: one is a protocol
/// violation that must abort the stream, the other is an ordinary
/// network-capacity drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadVerdict {
    /// Within both limits: encode and send it.
    Sendable,
    /// Longer than the tunnel can currently carry. RFC 9298 §5: discard it, as
    /// UDP semantics allow, and count the drop. Not an error.
    DropOverCapacity {
        /// Length of the payload that was dropped.
        payload_len: usize,
        /// Payload bytes the tunnel can currently carry, from
        /// [`tunnel_capacity`].
        capacity: usize,
    },
    /// Longer than [`MAX_UDP_PAYLOAD_LEN`]. RFC 9298 §5: a sender MUST NOT
    /// send it, and a receiver MUST abort the request stream.
    RejectOverProtocolMax {
        /// Length of the offending payload.
        payload_len: usize,
    },
}

impl PayloadVerdict {
    /// Whether the payload may be encoded and handed to the tunnel.
    pub fn is_sendable(&self) -> bool {
        matches!(self, PayloadVerdict::Sendable)
    }

    /// Whether the payload must be silently discarded (RFC 9298 §5).
    pub fn must_drop(&self) -> bool {
        matches!(self, PayloadVerdict::DropOverCapacity { .. })
    }

    /// Whether the payload violates the protocol maximum, so a sender must
    /// refuse it and a receiver must abort the stream (RFC 9298 §5).
    pub fn must_abort(&self) -> bool {
        matches!(self, PayloadVerdict::RejectOverProtocolMax { .. })
    }
}

/// Classify a UDP payload against the two independent RFC 9298 §5 limits.
///
/// `capacity` is the payload budget of the tunnel right now, normally from
/// [`tunnel_capacity`]. The protocol maximum is checked first, because
/// exceeding it is fatal to the stream regardless of how much room the tunnel
/// happens to have.
pub fn classify_payload(payload_len: usize, capacity: usize) -> PayloadVerdict {
    if payload_len > MAX_UDP_PAYLOAD_LEN {
        return PayloadVerdict::RejectOverProtocolMax { payload_len };
    }
    if payload_len > capacity {
        return PayloadVerdict::DropOverCapacity {
            payload_len,
            capacity,
        };
    }
    PayloadVerdict::Sendable
}

/// Payload bytes that fit in one datagram of the outer connection, i.e. the
/// inner MTU (RFC 9298 §5).
///
/// `max_datagram_size` is the outer connection's current maximum datagram
/// size. The two varint prefixes are subtracted from it; a budget too small to
/// even hold the prefixes yields `0`, which makes [`classify_payload`] drop
/// everything until the outer connection reports more room.
pub fn tunnel_capacity(
    max_datagram_size: usize,
    quarter_stream_id: QuarterStreamId,
    context_id: u64,
) -> Result<usize, CodecError> {
    let overhead = datagram_header_len(quarter_stream_id, context_id)?;
    Ok(max_datagram_size
        .saturating_sub(overhead)
        .min(MAX_UDP_PAYLOAD_LEN))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- varint ------------------------------------------------------------

    #[test]
    fn varint_roundtrip_covers_every_width() {
        // One value per encoded width, plus each width's boundaries.
        let cases: &[(u64, usize)] = &[
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (VARINT_MAX, 8),
        ];
        for &(value, width) in cases {
            assert_eq!(varint_len(value).unwrap(), width, "width of {value}");
            let mut buf = Vec::new();
            encode_varint(value, &mut buf).unwrap();
            assert_eq!(buf.len(), width, "encoded width of {value}");
            let mut pos = 0;
            assert_eq!(decode_varint(&buf, &mut pos).unwrap(), value);
            assert_eq!(pos, width);
        }
    }

    #[test]
    fn varint_matches_rfc9000_appendix_a1_vectors() {
        // RFC 9000 Appendix A.1 sample encodings.
        assert_eq!(encoded(37), vec![0x25]);
        assert_eq!(encoded(15_293), vec![0x7b, 0xbd]);
        assert_eq!(encoded(494_878_333), vec![0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(
            encoded(151_288_809_941_952_652),
            vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]
        );
    }

    #[test]
    fn varint_accepts_non_minimal_encoding() {
        // RFC 9000 §16 permits padding a value into a wider encoding.
        let mut pos = 0;
        assert_eq!(decode_varint(&[0x40, 0x25], &mut pos).unwrap(), 37);
        assert_eq!(pos, 2);
    }

    #[test]
    fn varint_rejects_out_of_range_value() {
        let value = VARINT_MAX + 1;
        assert_eq!(varint_len(value), Err(CodecError::VarintOutOfRange(value)));
        let mut buf = Vec::new();
        assert_eq!(
            encode_varint(value, &mut buf),
            Err(CodecError::VarintOutOfRange(value))
        );
        assert!(buf.is_empty(), "nothing is written on rejection");
    }

    #[test]
    fn varint_rejects_truncated_input() {
        let mut pos = 0;
        assert!(matches!(
            decode_varint(&[], &mut pos),
            Err(CodecError::Truncated { .. })
        ));
        // A 4-byte header with only 2 bytes present.
        let mut pos = 0;
        assert_eq!(
            decode_varint(&[0x9d, 0x7f], &mut pos),
            Err(CodecError::Truncated {
                field: "varint",
                needed: 2
            })
        );
        assert_eq!(pos, 0, "position is untouched on failure");
    }

    fn encoded(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_varint(value, &mut buf).unwrap();
        buf
    }

    // -- quarter stream id -------------------------------------------------

    /// Shorthand for a quarter ID derived from a raw stream ID.
    fn quarter(raw_stream_id: u64) -> QuarterStreamId {
        QuarterStreamId::from_request_stream_id(raw_stream_id).unwrap()
    }

    #[test]
    fn quarter_stream_id_divides_by_four() {
        assert_eq!(quarter(0).value(), 0);
        assert_eq!(quarter(4).value(), 1);
        assert_eq!(quarter(44).value(), 11);
        // A quarter ID that needs a multi-byte varint: 256 / 4 = 64 -> 2 bytes.
        assert_eq!(quarter(256).value(), 64);
        assert_eq!(varint_len(quarter(256).value()).unwrap(), 2);
    }

    #[test]
    fn quarter_stream_id_constructors_agree_on_the_conversion() {
        // The whole point of the newtype: `new` takes an already-quartered
        // value, `from_request_stream_id` takes a raw stream ID. These pairs
        // must denote the same stream.
        for (raw, already_quartered) in [(0_u64, 0_u64), (4, 1), (44, 11), (256, 64), (1000, 250)] {
            assert_eq!(
                QuarterStreamId::from_request_stream_id(raw),
                Ok(QuarterStreamId::new(already_quartered)),
                "raw {raw} should equal quarter {already_quartered}"
            );
        }
        // `new` performs no division, so mixing up the units is observable.
        assert_ne!(QuarterStreamId::new(4), QuarterStreamId::new(1));
        // ...except at zero, which is exactly why the first tunnel on a
        // connection works even when the units are confused.
        assert_eq!(QuarterStreamId::new(0), quarter(0));
    }

    #[test]
    fn quarter_stream_id_accessors_agree() {
        let id = QuarterStreamId::new(11);
        assert_eq!(id.value(), 11);
        assert_eq!(id.into_inner(), 11);
    }

    #[test]
    fn quarter_stream_id_is_usable_as_a_routing_key() {
        // Hash + Eq, because the integration layer keys its tunnel table on it.
        let mut tunnels = std::collections::HashMap::new();
        tunnels.insert(QuarterStreamId::new(0), "first");
        tunnels.insert(QuarterStreamId::new(1), "second");
        assert_eq!(tunnels.get(&quarter(4)), Some(&"second"));
        assert_eq!(tunnels.len(), 2);
    }

    #[test]
    fn quarter_stream_id_rejects_non_request_streams() {
        for stream_id in [1_u64, 2, 3, 5, 6, 7] {
            assert_eq!(
                QuarterStreamId::from_request_stream_id(stream_id),
                Err(CodecError::NotARequestStream { stream_id })
            );
        }
        // `new` deliberately accepts anything: its argument is already a
        // quarter value, so there is nothing to validate.
        assert_eq!(QuarterStreamId::new(3).value(), 3);
    }

    #[test]
    fn request_stream_id_is_the_inverse() {
        for stream_id in [0_u64, 4, 44, 256, 4 * VARINT_MAX] {
            assert_eq!(quarter(stream_id).request_stream_id().unwrap(), stream_id);
        }
        assert_eq!(
            QuarterStreamId::new(VARINT_MAX + 1).request_stream_id(),
            Err(CodecError::VarintOutOfRange(VARINT_MAX + 1))
        );
    }

    // -- datagram encoding -------------------------------------------------

    #[test]
    fn datagram_encodes_both_varint_prefixes() {
        // Stream 4 -> quarter 1 (1 byte), context 0 (1 byte).
        let encoded = encode_udp_payload(quarter(4), b"ping").unwrap();
        assert_eq!(encoded, vec![0x01, 0x00, b'p', b'i', b'n', b'g']);
        assert_eq!(datagram_header_len(quarter(4), 0).unwrap(), 2);
    }

    #[test]
    fn datagram_encodes_the_quarter_value_verbatim() {
        // A value already quartered by the caller is written through untouched.
        assert_eq!(
            encode_udp_payload(QuarterStreamId::new(1), b"ping").unwrap(),
            encode_udp_payload(quarter(4), b"ping").unwrap()
        );
        assert_eq!(
            encode_udp_payload(QuarterStreamId::new(1), b"x").unwrap(),
            vec![0x01, 0x00, b'x']
        );
    }

    #[test]
    fn datagram_encodes_multi_byte_quarter_stream_id() {
        // Stream 1000 -> quarter 250. 250 > 63, so it takes the 2-byte form
        // 0x40FA rather than a single byte.
        let encoded = encode_udp_payload(quarter(1000), b"x").unwrap();
        assert_eq!(encoded, vec![0x40, 0xfa, 0x00, b'x']);
        assert_eq!(datagram_header_len(quarter(1000), 0).unwrap(), 3);

        // Stream 4 * 20000 -> quarter 20000 -> 4-byte varint.
        let encoded = encode_udp_payload(quarter(80_000), b"x").unwrap();
        assert_eq!(encoded, vec![0x80, 0x00, 0x4e, 0x20, 0x00, b'x']);
        assert_eq!(datagram_header_len(quarter(80_000), 0).unwrap(), 5);
    }

    #[test]
    fn datagram_roundtrips_with_context_zero() {
        let payload = b"inner quic initial";
        let encoded = encode_udp_payload(quarter(1000), payload).unwrap();
        let decoded = decode_datagram(&encoded).unwrap();
        assert_eq!(
            decoded,
            HttpDatagram::UdpPayload {
                quarter_stream_id: QuarterStreamId::new(250),
                payload,
            }
        );
        assert_eq!(decoded.quarter_stream_id(), quarter(1000));
        assert_eq!(decoded.udp_payload(), Some(&payload[..]));
        assert_eq!(
            decoded.quarter_stream_id().request_stream_id().unwrap(),
            1000
        );
    }

    #[test]
    fn datagram_with_empty_payload_is_valid() {
        let encoded = encode_udp_payload(quarter(4), b"").unwrap();
        assert_eq!(
            decode_datagram(&encoded).unwrap(),
            HttpDatagram::UdpPayload {
                quarter_stream_id: QuarterStreamId::new(1),
                payload: b"",
            }
        );
    }

    #[test]
    fn datagram_with_non_zero_context_is_dropped_not_an_error() {
        // RFC 9298 §5: an unknown context is discarded, never an error.
        let encoded = encode_datagram(quarter(4), 7, b"compressed?").unwrap();
        let decoded = decode_datagram(&encoded).expect("unknown context must decode");
        assert_eq!(
            decoded,
            HttpDatagram::UnknownContext {
                quarter_stream_id: QuarterStreamId::new(1),
                context_id: 7,
            }
        );
        assert_eq!(decoded.udp_payload(), None, "payload is not surfaced");
        assert_eq!(decoded.quarter_stream_id(), QuarterStreamId::new(1));
    }

    #[test]
    fn datagram_with_large_non_zero_context_is_dropped() {
        let encoded = encode_datagram(quarter(4), 16_384, b"..").unwrap();
        assert_eq!(
            decode_datagram(&encoded).unwrap(),
            HttpDatagram::UnknownContext {
                quarter_stream_id: QuarterStreamId::new(1),
                context_id: 16_384,
            }
        );
    }

    #[test]
    fn datagram_rejects_corrupt_input() {
        // Empty datagram: no quarter stream ID at all.
        assert!(matches!(
            decode_datagram(&[]),
            Err(CodecError::Truncated { .. })
        ));
        // Quarter stream ID present, context ID missing entirely.
        assert!(matches!(
            decode_datagram(&[0x01]),
            Err(CodecError::Truncated { .. })
        ));
        // A 2-byte quarter stream ID header with only one byte of body, so the
        // context ID never starts.
        assert!(matches!(
            decode_datagram(&[0x40]),
            Err(CodecError::Truncated { .. })
        ));
        // Context ID claims 8 bytes but only 3 follow.
        assert!(matches!(
            decode_datagram(&[0x01, 0xc0, 0x00, 0x00]),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn datagram_encoding_rejects_non_request_stream() {
        // The check now lives in the constructor, so a bad stream ID can never
        // reach the encoder in the first place.
        assert_eq!(
            QuarterStreamId::from_request_stream_id(5),
            Err(CodecError::NotARequestStream { stream_id: 5 })
        );
    }

    #[test]
    fn datagram_encoding_rejects_unencodable_quarter_stream_id() {
        assert_eq!(
            encode_udp_payload(QuarterStreamId::new(VARINT_MAX + 1), b"x"),
            Err(CodecError::VarintOutOfRange(VARINT_MAX + 1))
        );
    }

    // -- capsules ----------------------------------------------------------

    /// Build one capsule: type, length, value.
    fn capsule_bytes(capsule_type: u64, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(capsule_type, &mut out).unwrap();
        encode_varint(value.len() as u64, &mut out).unwrap();
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn capsule_parser_reads_type_and_length() {
        let bytes = capsule_bytes(0x00, b"datagram");
        let capsules = parse_capsules(&bytes).unwrap();
        assert_eq!(capsules.len(), 1);
        assert_eq!(capsules[0].capsule_type, 0x00);
        assert_eq!(capsules[0].value, b"datagram");
    }

    /// `peek_header` reads the Type and Length without needing the Value, and
    /// reports the header's own width so a caller can step over it.
    #[test]
    fn peek_header_reads_the_header_without_the_value() {
        // type 0x1234 (2-byte varint), length 1000 (2-byte varint), and only
        // 4 bytes of a 1000-byte value present.
        let mut bytes = Vec::new();
        encode_varint(0x1234, &mut bytes).unwrap();
        encode_varint(1_000, &mut bytes).unwrap();
        let header_len = bytes.len();
        bytes.extend_from_slice(b"abcd");

        let header = CapsuleParser::new(&bytes)
            .peek_header()
            .expect("the header is complete even though the value is not")
            .expect("a capsule starts here");
        assert_eq!(header.capsule_type, 0x1234);
        assert_eq!(header.length, 1_000);
        assert_eq!(header.header_len, header_len);

        // And `next_capsule` on the same input still says "need more data",
        // which is the difference the peek exists to exploit.
        assert!(matches!(
            CapsuleParser::new(&bytes).next_capsule(),
            Err(CodecError::Truncated { .. })
        ));
    }

    /// A length no machine can address is reported as a number, not an error:
    /// the decision to skip it belongs to the caller, and making this a
    /// failure would force buffering-or-dying all over again.
    #[test]
    fn peek_header_reports_an_absurd_length_rather_than_failing() {
        let mut bytes = Vec::new();
        encode_varint(0x00, &mut bytes).unwrap();
        encode_varint(VARINT_MAX, &mut bytes).unwrap();

        let header = CapsuleParser::new(&bytes)
            .peek_header()
            .expect("an unusable length is still a readable header")
            .expect("a capsule starts here");
        assert_eq!(header.length, VARINT_MAX);
    }

    /// Exhausted input is `Ok(None)`, and a half-arrived header is
    /// `Truncated` — the same two "nothing to do yet" signals `next_capsule`
    /// gives, so a caller can treat them alike.
    #[test]
    fn peek_header_distinguishes_exhausted_from_truncated() {
        assert_eq!(CapsuleParser::new(&[]).peek_header().unwrap(), None);
        assert!(matches!(
            CapsuleParser::new(&[0x40]).peek_header(),
            Err(CodecError::Truncated { .. })
        ));
        // Type read, length missing.
        assert!(matches!(
            CapsuleParser::new(&[0x00]).peek_header(),
            Err(CodecError::Truncated { .. })
        ));
    }

    /// Peeking does not advance the parser: two peeks in a row see the same
    /// capsule, and a following `next_capsule` still returns it.
    #[test]
    fn peek_header_does_not_consume() {
        let bytes = capsule_bytes(0x42, b"abc");
        let parser = CapsuleParser::new(&bytes);
        let first = parser.peek_header().unwrap().unwrap();
        let second = parser.peek_header().unwrap().unwrap();
        assert_eq!(first, second);

        let mut parser = CapsuleParser::new(&bytes);
        let _ = parser.peek_header().unwrap().unwrap();
        let capsule = parser.next_capsule().unwrap().expect("still there");
        assert_eq!(capsule.capsule_type, 0x42);
        assert_eq!(capsule.value, b"abc");
    }

    #[test]
    fn capsule_parser_skips_unknown_types_and_continues() {
        // RFC 9297 §3.2: skip what you do not know, keep parsing the next one.
        let mut stream = capsule_bytes(0x1234, b"unknown");
        stream.extend_from_slice(&capsule_bytes(0x00, b"known"));
        stream.extend_from_slice(&capsule_bytes(0x3fff_ffff_ffff_ffff, b""));

        let capsules = parse_capsules(&stream).unwrap();
        assert_eq!(capsules.len(), 3);
        assert_eq!(capsules[0].capsule_type, 0x1234);
        assert_eq!(capsules[1].capsule_type, 0x00);
        assert_eq!(capsules[1].value, b"known");
        assert_eq!(capsules[2].capsule_type, 0x3fff_ffff_ffff_ffff);
        assert!(capsules[2].value.is_empty());

        // The caller-side skip: ignore every type it does not implement and it
        // still finds the one it does.
        let known: Vec<_> = capsules.iter().filter(|c| c.capsule_type == 0).collect();
        assert_eq!(known.len(), 1);
    }

    #[test]
    fn capsule_parser_reports_exhaustion_not_an_error() {
        let bytes = capsule_bytes(0x00, b"a");
        let mut parser = CapsuleParser::new(&bytes);
        assert!(parser.next_capsule().unwrap().is_some());
        assert_eq!(parser.next_capsule().unwrap(), None);
        assert_eq!(parser.offset(), bytes.len());
        assert!(parser.remaining().is_empty());
    }

    #[test]
    fn capsule_parser_rejects_truncated_value() {
        // Declares 8 bytes of value, supplies 3.
        let bytes = [0x00_u8, 0x08, b'a', b'b', b'c'];
        assert_eq!(
            parse_capsules(&bytes),
            Err(CodecError::Truncated {
                field: "capsule value",
                needed: 5,
            })
        );
    }

    #[test]
    fn capsule_parser_rejects_truncated_header() {
        // Type only, no length field.
        assert!(matches!(
            parse_capsules(&[0x00]),
            Err(CodecError::Truncated { .. })
        ));
        // Length field header announcing 4 bytes, only 2 present.
        assert!(matches!(
            parse_capsules(&[0x00, 0x80, 0x00]),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn capsule_parser_rejects_truncation_after_a_good_capsule() {
        let mut stream = capsule_bytes(0x00, b"complete");
        // Type 0x1ff parses, then the length field's 2-byte header is cut short.
        stream.extend_from_slice(&[0x41, 0xff, 0x70]);
        assert!(matches!(
            parse_capsules(&stream),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn capsule_parser_rejects_absurd_length() {
        // Length 2^62-1 cannot be satisfied and cannot fit usize on 32-bit.
        let mut bytes = Vec::new();
        encode_varint(0x00, &mut bytes).unwrap();
        encode_varint(VARINT_MAX, &mut bytes).unwrap();
        bytes.extend_from_slice(b"short");
        assert!(matches!(
            parse_capsules(&bytes),
            Err(CodecError::Truncated { .. }) | Err(CodecError::CapsuleLengthOverflow { .. })
        ));
    }

    #[test]
    fn capsule_parser_stays_poisoned_after_a_failure() {
        let bytes = [0x00_u8, 0x08, b'a'];
        let mut parser = CapsuleParser::new(&bytes);
        assert!(parser.next_capsule().is_err());
        assert!(
            parser.next_capsule().is_err(),
            "a failed parser must not resynchronize"
        );
    }

    // -- URI template ------------------------------------------------------

    #[test]
    fn uri_template_builds_the_rfc9298_path() {
        assert_eq!(
            build_connect_udp_path("example.com", 443).unwrap(),
            "/.well-known/masque/udp/example.com/443/"
        );
        assert_eq!(
            build_connect_udp_path("192.0.2.6", 443).unwrap(),
            "/.well-known/masque/udp/192.0.2.6/443/"
        );
    }

    #[test]
    fn uri_template_percent_encodes_ipv6_colons() {
        // RFC 9298 §3: the colons of an IPv6 literal MUST be percent-encoded.
        assert_eq!(
            build_connect_udp_path("2001:db8::42", 443).unwrap(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
        // Bracketed form, as it appears in a URL authority.
        assert_eq!(
            build_connect_udp_path("[2001:db8::42]", 443).unwrap(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
        assert!(!build_connect_udp_path("2001:db8::42", 443)
            .unwrap()
            .contains(':'));
    }

    #[test]
    fn uri_template_escapes_other_reserved_characters() {
        // Slash, percent, space and non-ASCII must not leak into the path.
        assert_eq!(
            build_connect_udp_path("a/b", 1).unwrap(),
            "/.well-known/masque/udp/a%2Fb/1/"
        );
        assert_eq!(
            build_connect_udp_path("a%b", 1).unwrap(),
            "/.well-known/masque/udp/a%25b/1/"
        );
        assert_eq!(
            build_connect_udp_path("a b", 1).unwrap(),
            "/.well-known/masque/udp/a%20b/1/"
        );
        assert_eq!(
            build_connect_udp_path("smörgås", 1).unwrap(),
            "/.well-known/masque/udp/sm%C3%B6rg%C3%A5s/1/"
        );
        // Unreserved characters survive untouched.
        assert_eq!(
            build_connect_udp_path("a-b_c.d~e9", 1).unwrap(),
            "/.well-known/masque/udp/a-b_c.d~e9/1/"
        );
    }

    #[test]
    fn uri_template_rejects_empty_host() {
        assert_eq!(
            build_connect_udp_path("", 443),
            Err(CodecError::EmptyTargetHost)
        );
        assert_eq!(
            build_connect_udp_path("[]", 443),
            Err(CodecError::EmptyTargetHost)
        );
    }

    #[test]
    fn uri_template_checks_port_boundaries() {
        assert_eq!(
            build_connect_udp_path("example.com", 0),
            Err(CodecError::InvalidTargetPort { port: 0 })
        );
        assert_eq!(
            build_connect_udp_path("example.com", 1).unwrap(),
            "/.well-known/masque/udp/example.com/1/"
        );
        assert_eq!(
            build_connect_udp_path("example.com", 65_535).unwrap(),
            "/.well-known/masque/udp/example.com/65535/"
        );
    }

    // -- payload limits ----------------------------------------------------

    #[test]
    fn payload_within_both_limits_is_sendable() {
        let verdict = classify_payload(1200, 1350);
        assert_eq!(verdict, PayloadVerdict::Sendable);
        assert!(verdict.is_sendable());
        assert!(!verdict.must_drop());
        assert!(!verdict.must_abort());
    }

    #[test]
    fn payload_at_the_capacity_boundary_is_sendable() {
        assert_eq!(classify_payload(1350, 1350), PayloadVerdict::Sendable);
        assert_eq!(
            classify_payload(1351, 1350),
            PayloadVerdict::DropOverCapacity {
                payload_len: 1351,
                capacity: 1350,
            }
        );
    }

    #[test]
    fn payload_over_capacity_is_dropped_not_fatal() {
        // RFC 9298 §5: MTU-limited datagrams are discarded, not errors.
        let verdict = classify_payload(4000, 1350);
        assert!(verdict.must_drop());
        assert!(!verdict.must_abort());
    }

    #[test]
    fn payload_at_the_protocol_maximum_boundary() {
        // 65527 is still legal; 65528 is not.
        assert_eq!(
            classify_payload(MAX_UDP_PAYLOAD_LEN, MAX_UDP_PAYLOAD_LEN),
            PayloadVerdict::Sendable
        );
        let over = MAX_UDP_PAYLOAD_LEN + 1;
        assert_eq!(
            classify_payload(over, MAX_UDP_PAYLOAD_LEN),
            PayloadVerdict::RejectOverProtocolMax { payload_len: over }
        );
    }

    #[test]
    fn protocol_maximum_wins_over_capacity() {
        // Over both limits: the fatal verdict must win, because the stream has
        // to be aborted rather than the datagram quietly dropped.
        let over = MAX_UDP_PAYLOAD_LEN + 1;
        let verdict = classify_payload(over, 1350);
        assert_eq!(
            verdict,
            PayloadVerdict::RejectOverProtocolMax { payload_len: over }
        );
        assert!(verdict.must_abort());
        assert!(!verdict.must_drop());
    }

    #[test]
    fn tunnel_capacity_subtracts_the_two_prefixes() {
        // Stream 4: 1-byte quarter ID + 1-byte context.
        assert_eq!(tunnel_capacity(1350, quarter(4), 0).unwrap(), 1348);
        // Stream 80_000: 4-byte quarter ID + 1-byte context.
        assert_eq!(tunnel_capacity(1350, quarter(80_000), 0).unwrap(), 1345);
    }

    #[test]
    fn tunnel_capacity_is_clamped_at_both_ends() {
        // Too small to hold even the prefixes -> nothing is sendable.
        assert_eq!(tunnel_capacity(1, quarter(4), 0).unwrap(), 0);
        assert!(classify_payload(1, tunnel_capacity(1, quarter(4), 0).unwrap()).must_drop());
        // An enormous outer datagram never lifts the protocol maximum.
        assert_eq!(
            tunnel_capacity(1 << 20, quarter(4), 0).unwrap(),
            MAX_UDP_PAYLOAD_LEN
        );
    }

    #[test]
    fn tunnel_capacity_rejects_unencodable_quarter_stream_id() {
        assert_eq!(
            tunnel_capacity(1350, QuarterStreamId::new(VARINT_MAX + 1), 0),
            Err(CodecError::VarintOutOfRange(VARINT_MAX + 1))
        );
    }
}
