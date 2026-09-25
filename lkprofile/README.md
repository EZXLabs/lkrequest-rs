# lkprofile

`lkprofile` parses captured TLS ClientHello and HTTP/2 frame data into structured fingerprint profiles.

It is an internal workspace library used by capture, conversion, and regression tooling. The crate is not published independently.

## Capabilities

- parse TLS ClientHello fields and extension order;
- derive `lktls::TlsProfile` data;
- parse HTTP/2 frame sequences and fingerprint-relevant settings;
- normalize and hash captured structures for comparison;
- serialize profile data for tooling and fixtures.

Parsing a capture does not by itself establish browser fidelity. Stable fields, randomized values, platform differences, Finch experiments, and request-context behavior must be evaluated separately.

## Validation

```bash
cargo test -p lkprofile
cargo doc -p lkprofile --no-deps
```

## License

Licensed under the Apache License 2.0.
