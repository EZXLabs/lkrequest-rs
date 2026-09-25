//! MASQUE CONNECT-UDP for `lkrequest`.
//!
//! Experimental: MASQUE-specific APIs and proxy interoperability may change
//! while validation against independent proxy implementations is pending.
//!
//! This crate carries the client side of proxying UDP over HTTP: RFC 9298
//! (Proxying UDP in HTTP, "CONNECT-UDP") layered on RFC 9297 (HTTP Datagrams
//! and the Capsule Protocol). It exists as its own crate because the wire
//! format has no dependency on TLS fingerprints, sessions or sockets, and is
//! far easier to test and audit against the RFCs on its own.
//!
//! ## What is here today
//!
//! Two layers, neither of which performs I/O.
//!
//! [`codec`] is the pure wire layer:
//!
//! | Item | Purpose | RFC |
//! |---|---|---|
//! | [`encode_varint`] / [`decode_varint`] / [`varint_len`] | QUIC variable-length integers | 9000 §16 |
//! | [`QuarterStreamId`] | The stream identifier datagrams are routed on | 9297 §2.1 |
//! | [`encode_datagram`] / [`decode_datagram`] | `[quarter stream ID][context ID][payload]` | 9297 §2.1, 9298 §4 |
//! | [`CapsuleParser`] | Capsule type/length framing, skipping unknown types | 9297 §3.2, §3.3 |
//! | [`build_connect_udp_path`] | URI Template expansion for the `:path` | 9298 §3 |
//! | [`classify_payload`] / [`tunnel_capacity`] | The two payload size limits | 9298 §5 |
//!
//! [`tunnel`] is the Sans-I/O state machine built on it:
//!
//! | Item | Purpose | RFC |
//! |---|---|---|
//! | [`TunnelConfig`] / [`ConnectUdpRequest`] | What to ask the proxy for, as a structured request | 9298 §2, §3 |
//! | [`AuthHeader`] | The caller-chosen proxy authentication field | 9298 §7 |
//! | [`TunnelDriver`] | `start` / `feed_response` / `feed_stream` / `progress`, plus the datagram channel | 9298 §3.5, 9297 §3 |
//! | [`TunnelTable`] / [`Dispatch`] | Demultiplexing connection-level datagrams onto tunnels | 9297 §2.1 |
//!
//! Nothing here performs I/O, opens a socket or reads a clock. The bridge that
//! does — a `quinn::AsyncUdpSocket` carrying an inner QUIC connection over an
//! outer HTTP/3 connection, pumping both channels — lives in `lkrequest`,
//! because it can only be built against this workspace's patched `h3` and
//! `quinn` forks. Keeping it out is what lets this crate stay usable with any
//! QUIC stack.
//!
//! The seam is deliberately shaped like `lktls`'s `HandshakeDriver`, with one
//! difference the protocol forces: MASQUE has two channels — the reliable,
//! ordered request stream carrying capsules, and unreliable, unordered,
//! droppable datagrams — so there is a feed and a send for each, not one
//! `feed`. See the [`tunnel`] module documentation for the driving loop.
//!
//! ## Three distinctions the API insists on
//!
//! Each is easy to get wrong by collapsing it into something coarser — the
//! first two into a single "error" path, the third into a bare `u64`:
//!
//! - A datagram whose Context ID is not 0 is **dropped, not rejected**. It
//!   decodes successfully as [`HttpDatagram::UnknownContext`]; only genuine
//!   framing damage produces a [`CodecError`].
//! - An oversized payload has two different causes.
//!   [`PayloadVerdict::RejectOverProtocolMax`] (over 65527 bytes) is a protocol
//!   violation that must abort the request stream, while
//!   [`PayloadVerdict::DropOverCapacity`] is an ordinary MTU-limited discard.
//! - A raw stream ID and a Quarter Stream ID are different numbers, so the API
//!   takes [`QuarterStreamId`] rather than `u64` and makes you say which unit
//!   you hold. Confusing them is quiet rather than loud: quarter ID `0` equals
//!   stream ID `0`, so the first tunnel on a connection works out either way
//!   and only the second one goes wrong. In this repository, `h3`'s
//!   `RequestStream::id()` returns the raw stream ID; convert it with
//!   [`QuarterStreamId::from_request_stream_id`].
//!
//! ## Example
//!
//! ```
//! use lkmasque::codec::{build_connect_udp_path, decode_datagram, encode_udp_payload,
//!                       classify_payload, tunnel_capacity, HttpDatagram, QuarterStreamId};
//!
//! // The `:path` of the CONNECT-UDP request (RFC 9298 §3).
//! let path = build_connect_udp_path("2001:db8::42", 443)?;
//! assert_eq!(path, "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/");
//!
//! // Request stream 4. `from_request_stream_id` divides by four; a caller
//! // holding an already-quartered value uses `QuarterStreamId::new(1)`.
//! let stream = QuarterStreamId::from_request_stream_id(4)?;
//! assert_eq!(stream, QuarterStreamId::new(1));
//!
//! // Send a UDP payload over it, once it is known to fit.
//! let payload = b"inner quic packet";
//! let capacity = tunnel_capacity(1350, stream, 0)?;
//! assert!(classify_payload(payload.len(), capacity).is_sendable());
//!
//! let datagram = encode_udp_payload(stream, payload)?;
//! assert_eq!(decode_datagram(&datagram)?.quarter_stream_id(), stream);
//! assert!(matches!(
//!     decode_datagram(&datagram)?,
//!     HttpDatagram::UdpPayload { .. }
//! ));
//! # Ok::<(), lkmasque::codec::CodecError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod tunnel;

pub use codec::{
    build_connect_udp_path, classify_payload, datagram_header_len, decode_datagram, decode_varint,
    encode_datagram, encode_datagram_into, encode_udp_payload, encode_varint, parse_capsules,
    tunnel_capacity, varint_len, Capsule, CapsuleHeader, CapsuleParser, CodecError, HttpDatagram,
    PayloadVerdict, QuarterStreamId, CONNECT_UDP_URI_TEMPLATE, CONTEXT_ID_UDP_PAYLOAD,
    MAX_UDP_PAYLOAD_LEN, VARINT_MAX,
};
pub use tunnel::{
    AuthHeader, CapsuleProtocolHeader, ConnectUdpRequest, Dispatch, MalformedResponseReason,
    OwnedCapsule, SendOutcome, TunnelAction, TunnelConfig, TunnelDriver, TunnelError, TunnelState,
    TunnelStats, TunnelTable, AUTHORIZATION_HEADER, CAPSULE_PROTOCOL_HEADER,
    CAPSULE_PROTOCOL_VALUE, CONNECT_UDP_METHOD, CONNECT_UDP_PROTOCOL, CONNECT_UDP_SCHEME,
    DEFAULT_MAX_STREAM_BUFFER, PROXY_AUTHORIZATION_HEADER,
};
