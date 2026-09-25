# lkrequest

`lkrequest` is a Rust HTTP client with byte-level control over TLS, HTTP/2, and optional HTTP/3/QUIC browser fingerprints.

The high-level object model separates immutable fingerprint configuration from browser-session state:

- `Client` — shared TLS/H2/H3 profile, defaults, limits, and timeouts;
- `Session` — a cookie jar that sends cookies in Chrome's order and can be read
  back with full attributes, connections, proxy configuration, HSTS, Alt-Svc,
  and QUIC fallback state;
- request builders — per-request method, headers, body, redirect, retry, and streaming behavior.

## Quick start

```rust,no_run
use lkrequest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_154())
        .build();
    let session = client.session().build();
    let response = session.get("https://example.com/").send().await?;

    println!("{}", response.status());
    println!("{}", response.text()?);
    Ok(())
}
```

## Features

- `quic-h3` — HTTP/3 and QUIC transport support;
- `masque` — experimental MASQUE CONNECT-UDP proxy support; implies `quic-h3`. MASQUE-specific APIs and proxy interoperability may change;
- `doh` — DNS over HTTPS through Hickory;
- `synthetic-fp` — synthetic fingerprint generation for controlled research;
- `telemetry` — aggregate operational counters;
- `network-e2e` — test-only public-network integration targets.

HTTP/2 always uses the fingerprint-controlled `lkh2` engine. The default
`h2-native` feature is a deprecated no-op alias: it will be removed from both
`lkrequest` and `lkh2` in 0.3.0, so applications that list it explicitly should
drop it now.

## Browser fidelity

| Family | Preset names | QUIC/H3 |
|---|---|---|
| Chrome | `chrome_131`, `chrome_144` through `chrome_154` | Requires `quic-h3` |
| Firefox | `firefox_133`, `firefox_147`, `firefox_156` | Not provided |
| Safari | `safari_18`, `safari_26` | Not provided |

All presets provide TLS and H2 profiles. Chrome 154.0.8037.58 and Firefox
156.0.1 were captured on Windows against public Cloudflare targets. Chrome 154
inherits Chrome 153's H3 SETTINGS; Firefox 156 provides only TLS/H2, even in a
`quic-h3` build. See the [support matrix](../docs/reference/presets.md) for
per-layer evidence.

Presets combine TLS, H2, optional QUIC/H3, protocol policy, and header ordering. Browser behavior can vary by version, platform, GREASE, Finch configuration, and request context. Treat committed fixtures as regression evidence, not as proof of every live-browser behavior.

Set User-Agent and other browser header values explicitly; the preset supplies
their ordering, not their values.

## Build and test

Git submodules are required for the patched Quinn and H3 dependencies.

```bash
git submodule update --init --recursive
cargo test -p lkrequest
cargo test -p lkrequest --features quic-h3
cargo doc -p lkrequest --all-features --no-deps
```

## License

Licensed under the Apache License 2.0.
