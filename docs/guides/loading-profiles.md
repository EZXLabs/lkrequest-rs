# Loading Profile Bundles

Use a complete v2 bundle when TLS, HTTP/2 behavior, QUIC/HTTP/3, ordering and
protocol policy must travel together. The loader performs no network activity.

## Rust

```rust,no_run
use lkrequest::{Client, ClientPreset};
use lkrequest::preset::{self, PresetDocument};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let preset = ClientPreset::from_json_file("preset.json")?;
let client = Client::builder().preset(preset).try_build()?;

// Export a built-in or supported custom preset as a reloadable document.
let document = PresetDocument::from_preset("chrome-157", &preset::chrome_157())?;
std::fs::write("chrome-157.json", document.to_json_string()?)?;
# Ok(())
# }
```

`from_json_str` and `from_json_slice` use the same loader. `PresetDocument`
retains the display name and optional metadata; `into_preset()` extracts the
runtime preset. `lkrequest::blocking::Client::builder().preset(preset).try_build()`
uses the same configuration checks.

For a runnable file export and validation example:

```sh
cargo run -p lkrequest --example preset_bundle -- export preset.json
cargo run -p lkrequest --example preset_bundle -- check preset.json
```

Enable `--features quic-h3` on both commands to include QUIC/H3. Loading a
non-null QUIC profile without that feature returns `feature_unavailable`.
Optional H3 discovery remains valid with a TCP-only bundle; a policy that
requires H3 needs a QUIC profile.

Applying a preset replaces all preset dimensions, including empty and null
order templates and the optional QUIC TLS profile. Later Rust builder calls can
override individual components. `try_build()` rechecks the final profiles for
builders using a preset; prefer it to the panicking `build()` for external data.

## C ABI

```c
lk_client_builder_t* builder = lk_client_builder_new();
lk_error_t* error = NULL;
if (lk_client_builder_set_preset_file(builder, "preset.json", 11, &error) != LK_OK) {
    /* Inspect lk_error_message and lk_error_get_diagnostics_json; free error. */
}
```

| Entry Point | Contract |
| --- | --- |
| `lk_client_builder_set_preset_json(builder, json, len, &error)` | Copies and validates a complete document before replacing builder state |
| `lk_client_builder_set_preset_file(builder, path, len, &error)` | Reads a caller-selected UTF-8 path with bounded file input |
| `lk_preset_export_json(name, len, out, capacity, &length, &error)` | Exports a named built-in as v2; query size with `out = NULL, capacity = 0`, then allocate `length + 1` bytes |

Feature discovery name: `preset-bundle-v2`. Output length excludes the NUL;
undersized export buffers receive no partial document. These functions do not
transfer buffer ownership to the library.

Load failures leave the builder unchanged. `set_preset_json(builder, NULL, 0,
&error)` removes the bundle override and restores the selected named preset.
A successful `set_preset` also removes the bundle override. Explicit component
setters take precedence over either source regardless of setter order; clear
the component override to use the bundle's value again.

Loader errors map to the existing `INVALID_CONFIG`, `RESOURCE_LIMIT_EXCEEDED`
or `IO` error codes. Error diagnostics additionally contain:

```json
{"preset_error":{"code":"duplicate_key","path":"/name","message":"duplicate JSON key"}}
```

`lk_preset_get_detail_json` remains a diagnostic snapshot. Use
`lk_preset_export_json` to obtain a complete reloadable document.

## Individual Profile Components

A complete bundle carries runtime policy and all profile layers. To replace only
one layer, Rust uses typed profiles:

```rust
use lkrequest::{Client, lkh2, lktls};

let client = Client::builder()
    .fingerprint(lktls::profile::presets::firefox_156())
    .h2_profile(lkh2::profile::firefox_156_h2())
    .build();
```

This does not install Firefox's default HTTP headers or protocol policy. Use
`preset::firefox_156()` for the complete high-level preset. `.quic_fingerprint()`
sets a separate TLS profile for QUIC, while `.quic_profile()` controls QUIC/H3
transport and HTTP behavior. `.clear_quic_fingerprint()` makes QUIC use the TCP
TLS profile; `.disable_http3()` removes the QUIC/H3 profile. These are different
operations, and neither a QUIC TLS profile nor a TLS 1.3 setting alone enables H3.

| C component setter | Input and reset behavior |
| --- | --- |
| `lk_client_builder_set_tls_profile_json` | Native editable `TlsProfile` JSON; `NULL, 0` restores the base TLS profile |
| `lk_client_builder_set_h2_profile_json` | Native H2 data fields; `NULL, 0` restores the selected H2 preset or base profile |
| `lk_client_builder_set_quic_tls_profile_json` | Native TLS JSON with TLS 1.3 enabled; `NULL, 0` restores the base QUIC TLS profile |
| `lk_client_builder_set_quic_profile_json` | Native QUIC/H3 JSON; use `lk_client_builder_disable_http3` to remove H3 |
| `lk_client_builder_clear_quic_fingerprint` | Explicitly reuse effective TCP TLS for QUIC, rather than restore the preset's separate QUIC TLS profile |

The setters copy their input, limit each JSON input to 1 MiB and validate before
changing the override. A rejected input leaves the previous override intact.
Their arguments are `(builder, json_ptr, json_len)`, returning `lk_status_t`;
they do not take the bundle loader's `out_error` argument. Clear/reset behavior
is specific to each setter; `NULL, 0` is not a universal disable convention.

Component overrides take precedence over named and JSON presets regardless of
C setter order. Individual H2 JSON does **not** reconstruct H2 runtime behavior:
it uses baseline behavior and rejects an explicit `behavior` field. Use a v2
bundle to carry HPACK, flow-control and write policies together. TLS JSON rejects
strict ClientHello mirror templates. QUIC setters require `quic-h3`.

Capability names are `tls-profile-json`, `h2-profile-json`, `quic-tls-profile-json`
and `quic-profile-json`; the last two depend on the library's build features.

## Document Contract

The format discriminator is `"format": "lkrequest-profile-bundle"`, with integer
`"schema_version": 2`. Obtain a complete starting file from the exporter.

| Field | Meaning |
| --- | --- |
| `name` | Display name, 1..256 bytes; never selects behavior |
| `tls_profile` | Editable TLS profile; strict ClientHello mirror templates are rejected |
| `quic_tls_profile` | Separate QUIC TLS profile, or explicit `null` to reuse TCP TLS |
| `h2_profile` | Native H2 data fields; `behavior` belongs in `runtime` |
| `quic_profile` | QUIC transport, packetization and H3 profile, or explicit `null` to disable H3 |
| `header_order` | Ordinary header names; an empty array removes the template |
| `h3_header_order` | H3-specific template; `null` reuses ordinary ordering |
| `cookie_order` | Cookie names, without values, or explicit `null` |
| `runtime` | Versioned executable policies, illustrated below |
| `metadata` | Optional bounded object; retained without affecting execution |

Every field except `metadata` must be present, including nullable fields. The
component data uses the TLS/H2/QUIC field names shown by the exporter; keep its
fields, including explicit nulls and false behavior flags. V2 requires complete
component objects rather than inheriting future native defaults. For QUIC,
all `u64` fields use canonical decimal **strings**, including SETTINGS pairs,
transport parameter IDs, priorities, packet numbers and CRYPTO offsets. Values
must fit a QUIC varint. Lengths, MTUs, H2 settings and small integers remain JSON
numbers. Numeric strings cannot contain signs, whitespace or leading zeros.

Example runtime for a TCP-only configuration:

```json
{
  "version": 1,
  "protocol": {
    "intent": "h2_only",
    "acquisition": {"type": "establish_best_available"},
    "upgrade": "off",
    "fallback": "no_fallback"
  },
  "tls_session_cache_partition": "unpartitioned",
  "h2_behavior": {
    "version": 1,
    "write": {
      "split_headers": true,
      "split_data": true,
      "max_data_frame_payload": 16375,
      "send_goaway_on_close": false,
      "separate_end_stream_data": false
    },
    "flow_control": {"type": "threshold", "ratio": 0.5},
    "hpack": "chromium"
  }
}
```

Flow control supports `immediate` or `threshold` with ratio `0.1..1.0`.
HPACK supports `indexed`, `chromium`, `firefox`, `safari` and
`adaptive_huffman` (incremental indexing, Huffman only when shorter).
`separate_end_stream_data` moves END_STREAM from a nonempty final DATA frame to
a following empty DATA frame before grouping writes. Arbitrary custom Rust
trait implementations must supply supported policy descriptors or export fails
with `unsupported_behavior`.

## Validation and Limits

Parsing rejects decoded duplicate keys, nested unknown runtime fields, invalid
UTF-8, trailing input, wrong types, unsupported versions and invalid enums.
Semantic checks cover TLS profile invariants and vector/payload bounds, H2
settings/windows/priorities, order templates, QUIC/H3 field bounds and policy
conflicts. Validation does not certify browser capture fidelity or guarantee a
particular server accepts a fingerprint.

Default budgets are 1 MiB input, depth 32, 65,536 JSON values, 4,096 entries per
container, 128 KiB per string and 256 KiB total opaque payloads. One hex payload
is limited to 65,535 decoded bytes (trust-anchor IDs: 255). File reads stop at
the input limit plus one byte. Rust hosts can configure `PresetLoader.limits`;
JSON has no authority to change limits. The first failure returns a stable code,
JSON Pointer and message. Loading cannot select proxy/CA/verification settings,
include other files or execute policy text.

## Legacy Snapshots

Unversioned snapshots, Hub v1 exports and `policy_snapshot` Debug strings are
not complete executable bundles. Normal loading returns
`legacy_bundle_incomplete`. Migrate with runtime settings explicitly chosen by
the application:

```rust,ignore
let document = PresetLoader::default().migrate_legacy_json(&legacy_bytes, runtime)?;
std::fs::write("preset-v2.json", document.to_json_string()?)?;
```

`runtime` is a typed `lkrequest::preset::PresetRuntime`. Migration preserves
legacy policy text as metadata and runs the standard v2 validation. It never
infers policies from the name or Debug output. Existing precision loss in a
legacy JSON producer cannot be recovered by migration.
