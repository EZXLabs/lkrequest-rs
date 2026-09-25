# lkquic

`lkquic` provides QUIC endpoint and connection management for `lkrequest` while keeping transport policy separate from the concrete backend.

## Responsibilities

- endpoint lifecycle and reuse strategies;
- QUIC connection bootstrap and connection requests;
- browser-oriented connection-ID generation;
- a pluggable `QuicBackend` abstraction;
- the default patched-Quinn backend and a lightweight test backend.

## Features

- `quinn-backend` — enabled by default; builds the real Quinn transport backend.

## Intended use

Application code normally uses `lkrequest` with the `quic-h3` feature. Use `lkquic` directly when implementing a transport backend, testing endpoint policy, or integrating QUIC connection management without the high-level HTTP session layer.

Fingerprint profiles themselves live in `lkh3`, while QUIC-native TLS is provided by `lktls-quic`.

## Validation

```bash
cargo test -p lkquic
cargo doc -p lkquic --no-deps
```

## License

Licensed under the Apache License 2.0.
