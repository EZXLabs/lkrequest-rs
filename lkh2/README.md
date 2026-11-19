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

The fingerprint-controlled engine is the only HTTP/2 implementation and is
always compiled. No backend feature is needed. For upgrading older Cargo
configurations, see the [0.3.0 migration notes](../CHANGELOG.md#upgrade-from-025).

## Fingerprint safety

`profile::chrome_155_h2()` and `profile::firefox_156_h2()` expose the current
Chrome and Firefox additions. Public captures retain Chrome 153's and Firefox
147's H2 settings respectively, so these functions reuse those configurations.
Use `lkrequest::preset::chrome_155()` or `firefox_156()` to pair H2 with the
matching TLS profile and header order. Per-version evidence is listed in the
[support matrix](../docs/reference/presets.md).

Changing frame grouping, batching, HPACK decisions, or write boundaries can change observable network behavior. Performance changes must be checked against the target browser capture as well as protocol tests.

## Request header warnings

The engine emits a `WARN` event on target `lkh2::request` with diagnostic
`h2.request_headers_noncompliant` when encoding connection-specific fields
(`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`)
or a `TE` value other than `trailers`. These fields violate
[RFC 9113 section 8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2)
and can cause a peer to reset the stream with `PROTOCOL_ERROR`.

The warning includes the H2 stream ID and offending field names, but no header
values or URL. Each encoded header block emits at most one warning. Enable a
Rust tracing subscriber or the existing FFI log callback at WARN level to
receive it. The check is skipped when that log target/level is disabled.

Headers, ordering, HPACK state and frame bytes are preserved: this is a
diagnostic, not automatic filtering or a complete RFC validator. It applies
only to the H2 engine; HTTP/1.1 requests do not trigger this diagnostic.

## Validation

```bash
cargo test -p lkh2
cargo doc -p lkh2 --no-deps
```

## License

Licensed under the Apache License 2.0.
