# lktls

`lktls` is the Sans-I/O TLS protocol engine used by `lkrequest` for byte-level browser fingerprint control.

It owns the TLS wire representation rather than network I/O:

- browser-profiled ClientHello construction;
- extension, cipher-suite, signature-algorithm, and key-share ordering;
- GREASE, ECH, ALPS, certificate compression, and session resumption;
- TLS 1.2 and TLS 1.3 handshake state machines;
- record protection, certificate verification, and key logging hooks.

## Intended use

Most applications should use the high-level `lkrequest` crate. Use `lktls` directly when building a custom transport adapter, analyzing serialized ClientHello bytes, or maintaining browser fingerprint profiles.

`lktls` performs no socket I/O and has no async runtime dependency. TCP integration lives in `lkrequest`; QUIC integration lives in `lktls-quic`.

## Fingerprint profiles

Built-in profiles are loaded from `profiles/*.json` and exposed through `lktls::profile::presets`.
The current Chrome and Firefox additions are `chrome_154()` and `firefox_156()`,
captured from Chrome 154.0.8037.58 and Firefox 156.0.1 on Windows.
`chrome_154_quic()` supplies the transport-specific QUIC ClientHello profile;
there is no `firefox_156_quic()` preset.

Profiles have different evidence levels, including captured, inherited, and
unverified fields; see the [support matrix](../docs/reference/presets.md).
Do not edit golden profiles merely to make a test pass; recapture the target
browser when its wire behavior changes.

## Validation

```bash
cargo test -p lktls
cargo bench -p lktls
cargo doc -p lktls --no-deps
```

## License

Licensed under the Apache License 2.0.
