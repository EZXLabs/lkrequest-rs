# lkmasque

`lkmasque` implements the client side of MASQUE CONNECT-UDP for `lkrequest`: RFC 9298 (Proxying UDP in HTTP) on top of RFC 9297 (HTTP Datagrams and the Capsule Protocol). It lets a QUIC/HTTP-3 connection to a target be tunneled through a MASQUE proxy, the UDP counterpart of the existing SOCKS5 UDP ASSOCIATE path.

This crate and `lkrequest`'s `masque` feature are experimental. MASQUE-specific APIs and proxy interoperability may change; validation against an independent proxy implementation is still pending.

## Responsibilities

- QUIC variable-length integer encoding and decoding (RFC 9000 §16);
- the two-layer HTTP Datagram payload `[quarter stream ID][context ID][payload]` (RFC 9297 §2.1, RFC 9298 §4), including the rule that an unrecognized Context ID is dropped rather than treated as an error (RFC 9298 §5);
- a `QuarterStreamId` newtype so a raw stream ID cannot be mistaken for a quartered one. The current `h3-quinn` returns a raw request stream ID, so integration code uses `QuarterStreamId::from_request_stream_id` to divide it by four;
- minimal Capsule framing: read the Capsule Type and Length, skip unknown types and continue with the next capsule, treat truncation or an unusable length as a malformed message (RFC 9297 §3.2, §3.3);
- expansion and validation of the CONNECT-UDP URI Template, including percent-encoding the colons of IPv6 literals (RFC 9298 §3);
- classification of a payload against the two independent size limits — the 65527-byte protocol maximum that must abort the stream and the tunnel's current capacity that is an ordinary drop (RFC 9298 §5);
- the tunnel state machine (`tunnel`): building the CONNECT-UDP request, validating the response against RFC 9298 §3.5 (2xx except 204/205/206, with no Content-Length, Content-Type, or Transfer-Encoding), reassembling capsules that arrive across several reads of the request stream, inner-MTU accounting, tunnel lifecycle, and a `TunnelTable` that demultiplexes connection-level datagrams by Quarter Stream ID. The optional `capsule-protocol` response field is recorded but is not required to open the tunnel.

## Boundaries

This crate is deliberately narrow.

- **No I/O.** Every function takes bytes, scalars or caller-supplied timestamps and returns bytes, actions or an error. Sockets, streams, timers and `async` live elsewhere; nothing here even reads a clock.
- **No HTTP type library.** `ConnectUdpRequest` is plain strings. RFC 8441's `:protocol` pseudo-header has no representation in the `http` crate's types anyway, and string pairs are what every QUIC/HTTP-3 stack can build a request from.
- **No capsule semantics.** Framing only; no capsule type is interpreted, because RFC 9297 §3.2 conformance needs nothing more than the ability to skip.
- **No fingerprint concerns.** The outer connection to a MASQUE proxy uses a default TLS configuration; the browser fingerprint belongs to the inner connection and is owned by `lktls` / `lkh3` / `lkquic`.
- **Only `thiserror` as a dependency**, so this layer stays cheap to build, test and audit against the RFCs.

The I/O bridge — a `quinn::AsyncUdpSocket` that carries an inner QUIC connection over an outer HTTP/3 connection, the H3 driver, the two-channel pump and failure isolation — lives in `lkrequest`, because it can only be built against this workspace's patched `h3` and `quinn` forks. The design lives in `design/masque-connect-udp-design.md`.

## Intended use

Most users should configure a MASQUE proxy through `lkrequest`. Use `lkmasque` directly when driving CONNECT-UDP from another QUIC stack, implementing a MASQUE endpoint, writing a test proxy, or debugging framing on the wire.

## Validation

```bash
cargo test -p lkmasque
cargo clippy -p lkmasque --all-targets -- -D warnings
cargo doc -p lkmasque --no-deps
```

## License

Licensed under the Apache License 2.0.
