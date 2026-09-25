# lkh2

`lkh2` is the fingerprint-controlled HTTP/2 engine used by `lkrequest`.

It provides frame-level control over behavior that mainstream HTTP/2 clients normally hide:

- SETTINGS order and values;
- connection and stream flow control;
- HPACK encoding strategy;
- pseudo-header and regular-header order;
- PRIORITY and RFC 9218 priority behavior;
- DATA frame sizing and write batching boundaries.

## Intended use

Most applications should use `lkrequest`, which connects `lkh2` to TLS, proxies, DNS, connection pooling, retries, and response handling. Use `lkh2` directly for custom transports, protocol experiments, offline serialization, or HTTP/2 fingerprint regression work.

The native fingerprint-controlled engine is the only HTTP/2 implementation. The
`h2-native` feature is a deprecated no-op alias kept for the 0.2.x line and will
be removed in 0.3.0; drop it from your feature list now.

## Fingerprint safety

`profile::chrome_154_h2()` and `profile::firefox_156_h2()` expose the current
Chrome and Firefox additions. Public captures retain Chrome 153's and Firefox
147's H2 settings respectively, so these functions reuse those configurations.
Use `lkrequest::preset::chrome_154()` or `firefox_156()` to pair H2 with the
matching TLS profile and header order. Per-version evidence is listed in the
[support matrix](../docs/reference/presets.md).

Changing frame grouping, batching, HPACK decisions, or write boundaries can change observable network behavior. Performance changes must be checked against the target browser capture as well as protocol tests.

## Validation

```bash
cargo test -p lkh2
cargo doc -p lkh2 --no-deps
```

## License

Licensed under the Apache License 2.0.
