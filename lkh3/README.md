# lkh3

`lkh3` contains the HTTP/3 and QUIC fingerprint profiles used by `lkrequest`, together with the thin H3 connection and request layer built on patched `h3` and Quinn crates.

## Responsibilities

- QUIC transport parameter values and wire order;
- connection-ID and Initial packet layout profiles, including Chromium's
  per-connection CRYPTO split with interleaved PING/PADDING
  (`QuicPacketizationProfile::initial_packet_chaos`);
- Chromium GREASE generation rules for H3 settings and frames
  (`H3Profile::chromium_grease`) and for reserved transport parameters
  (`QuicTransportParams::randomize_grease_shape`);
- HTTP/3 SETTINGS and QPACK configuration;
- pseudo-header order and RFC 9218 `PRIORITY_UPDATE` behavior;
- H3 connection, sender, response-stream, resumption, and 0-RTT integration.

## Intended use

Most users should enable `lkrequest`'s `quic-h3` feature. Use `lkh3` directly when maintaining QUIC/H3 browser profiles, validating transport parameters, or integrating the H3 layer into a custom client.

Browser presets may contain a mix of directly captured and explicitly inherited fields. A valid profile is not automatically proof that every layer was independently captured.

`chrome_155_quic()` and `chrome_155_h3()` have direct public Cloudflare
capture evidence from Windows Chrome 155.0.8059.40, including decrypted H3
SETTINGS and a successful H3 navigation. Stable fields match the previous model.

Chrome 155 also emits a control-stream `PRIORITY_UPDATE` for each allocated
request stream before HEADERS, including pooled requests and streaming uploads.
Preconnect sends SETTINGS and GREASE without targeting an unallocated request.
`H3Profile::request_priority_updates` selects this mode; older serialized and
custom profiles default to their existing startup `priority_updates` list.

For direct `H3Sender` integration, provide a `RequestPriorityUpdate` request
extension or a `priority` HTTP header. An unannotated request falls back to the
first profile priority value (or `u=3` if absent). The high-level `lkrequest`
client resolves priority from `.priority()`, request/default headers and resource
destination, independently of whether automatic HTTP header generation is on.

`chrome_154_quic()` provides the Chrome 154 QUIC/H3 profile. Its outgoing QUIC
fields were captured directly; H3 SETTINGS and navigation priority inherit the
completed Chrome 153 capture. The library does not provide Firefox 156 or Safari
QUIC/H3 presets. Firefox 156 QUIC Initial observations are research evidence,
not an implemented transport profile. See the [support matrix](../docs/reference/presets.md).

The repository depends on patched `h3` and `quinn` submodules. Initialize Git submodules before building.

## Validation

```bash
cargo test -p lkh3
cargo doc -p lkh3 --no-deps
```

## License

Licensed under the Apache License 2.0.
