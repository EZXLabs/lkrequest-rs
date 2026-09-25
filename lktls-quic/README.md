# lktls-quic

`lktls-quic` bridges the byte-exact TLS engine in `lktls` to the patched Quinn transport used by `lkrequest`.

QUIC carries TLS 1.3 inside the transport handshake. This crate lets Quinn use an `lktls::TlsProfile`, preserving the intended browser ClientHello, key schedule, handshake metadata, session resumption, and 0-RTT behavior.

## Responsibilities

- implement Quinn crypto traits on top of `lktls`;
- expose `LktlsQuicClientConfig` for QUIC client configuration;
- validate QUIC-specific TLS ticket and early-data requirements;
- emit QUIC ClientHello bytes for offline fingerprint regression tests.

## Intended use

This is an integration crate, not the primary application API. Most users should enable the `quic-h3` feature on `lkrequest`. Use `lktls-quic` directly only when integrating the `lktls` handshake engine with a custom Quinn-based client.

The repository depends on patched `quinn` and `quinn-proto` submodules. Initialize Git submodules before building.

## Validation

```bash
cargo test -p lktls-quic
cargo doc -p lktls-quic --no-deps
```

## License

Licensed under the Apache License 2.0.
