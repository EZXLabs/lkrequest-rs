# lkrequest-ffi

`lkrequest-ffi` is the stable C ABI facade for `lkrequest`.

It exposes the high-value parts of the Rust client to C/C++/Go/Python style bindings without leaking Rust async, ownership, or internal transport details across the ABI boundary.

## Build Output

`lkrequest-ffi` builds both:

- `cdylib`: native dynamic library for external language bindings
- `rlib`: internal Rust reuse and testing

Manifest: `lkrequest-ffi/Cargo.toml`.

Public C header (generated, **not committed** — git-ignored):

- `include/lkrequest.h`

`build.rs` regenerates it from the export surface via `cbindgen` on every
`cargo build` / `cargo test`. To produce or refresh it manually:

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

The Rust crate builds without `cbindgen`; in that case header generation is
skipped with a build warning.

## Object Model

Current exported opaque handles:

- `lk_client_t`
- `lk_session_t`
- `lk_request_t`
- `lk_response_t`
- `lk_streaming_response_t`
- `lk_error_t`
- `lk_op_t`
- `lk_proxy_pool_t`
- `lk_proxy_pool_builder_t`
- `lk_proxy_guard_t`
- `lk_session_pool_t`
- `lk_session_pool_builder_t`
- `lk_session_pool_guard_t`
- `lk_multipart_t`
- `lk_masque_config_t` (MASQUE outer-connection settings; needs the `masque`
  feature to be creatable, but the type exists in every build)

## Current Coverage

Implemented ABI surface includes:

- Sync + async request execution
- Streaming reads and chunk ops
- Response text / cookies / redirect history / diagnostics
- Streaming diagnostics and header-by-name lookup
- Session cookie CRUD and JSON readers for URL-matched or all-domain cookies,
  including domain/path, Secure, HttpOnly, SameSite and expiry attributes
- Session preconnect sync/async
- Session connection-pool stats / clear
- Request `cookie_override`
- Multipart/form-data handles and request integration
- ProxyPool builder / acquire / acquire_async / acquire_fresh / mark_bad
- Proxy configuration handles (`lk_proxy_config_*`): URL parsing including
  `masque://` (RFC 9298 CONNECT-UDP), username/password credentials, static HTTP
  credentials (`Preshared` / `PrivateToken` / `Bearer` …) and the choice of
  `Proxy-Authorization` vs `Authorization`. The Rust-side
  `ProxyCredential::Custom` authenticator is **Rust-only** — it is a trait
  object and cannot cross the C ABI.
- MASQUE outer-connection configuration (`lk_masque_config_*`): trust anchors
  (PEM bundle and DER), `use_native_certs`, `verify`, `server_name`, and the two
  tunnel-reclaim knobs — attachable to a client builder or to a proxy/session
  pool's CONNECT-UDP health-check probe. See **MASQUE outer configuration**
  below.
- SessionPool builder / acquire / acquire_async / acquire_fresh / mark_bad
- DNS preset / custom socket address / native cert toggle
- File logging and callback logging
- Fingerprint randomization policy (`lk_client_builder_set_randomize`)

## MASQUE outer configuration

MASQUE support is experimental and requires the opt-in `masque` feature. Its
dedicated configuration and proxy interoperability may change while independent
proxy testing is still pending. The feature does not change which C ABI symbols
are present; builds without it report an error when those symbols are used.

A `masque://` proxy URL says *where* the proxy is. It cannot say what the hop
*to* the proxy should trust — and that hop is an ordinary HTTP/3 connection with
ordinary TLS. A self-hosted or vendor-issued MASQUE proxy is normally fronted by
a private CA, so `lk_masque_config_t` is how a C caller names it.

This matters most for the proxy pool. The ordinary health check opens a TCP
connection and calls the proxy alive, which proves nothing about a MASQUE proxy,
so `masque://` proxies are skipped by default. Turning on the real CONNECT-UDP
probe without trust anchors would be worse than skipping: a privately-fronted
proxy would fail its handshake and be **blacklisted while healthy**. So the
probe and the anchors arrive together, through this handle.

| Entry point | Effect |
|---|---|
| `lk_masque_config_new(&out)` | settings at their defaults (OS trust store, name from the proxy URL, 120s idle timeout, 256 tunnels) |
| `lk_masque_config_add_ca_certs_pem(cfg, pem, len, &added)` | append every certificate in a PEM **bundle**; `added` is optional. A malformed bundle, or one holding no certificate, returns `LK_ERR` and appends nothing |
| `lk_masque_config_add_ca_cert_der(cfg, der, len)` | append one DER trust anchor; bad DER surfaces when the outer connection is built |
| `lk_masque_config_set_use_native_certs(cfg, enabled)` | trust the OS store (default on); turn it off for a private CA |
| `lk_masque_config_set_verify(cfg, enabled)` | verify the proxy's certificate (default on). `false` skips it on this hop only — **development only**, and a last resort: the anchors above are the fix for a private CA |
| `lk_masque_config_set_server_name(cfg, name, len)` | override SNI and the verified certificate name; `NULL` restores the proxy URL's host |
| `lk_masque_config_set_tunnel_idle_timeout(cfg, ms)` | retire an idle tunnel after `ms`; `0` never retires on idleness |
| `lk_masque_config_set_max_idle_tunnels(cfg, n)` | cap tunnels per outer connection, least recently active shed first; `0` removes the cap |
| `lk_masque_config_free(cfg)` | release it; `NULL` is a no-op |
| `lk_client_builder_set_masque_config(builder, cfg)` | use these settings on the request path |
| `lk_proxy_pool_builder_set_masque_tunnel_probe(builder, cfg)` | probe `masque://` proxies in this pool with a real CONNECT-UDP handshake, verified against `cfg` |
| `lk_session_pool_builder_set_masque_tunnel_probe(builder, cfg)` | the same, for a `SessionPool` |

Both consumers **copy** the settings, so one handle can feed both — which is
the usual arrangement, since the probe should judge a proxy the way the requests
will — and is freed exactly once.

```c
lk_masque_config_t *outer = NULL;
if (lk_masque_config_new(&outer) != LK_OK) { /* built without `masque` */ }

/* A privately-fronted proxy needs nothing from the OS store. */
lk_masque_config_set_use_native_certs(outer, false);
size_t added = 0;
if (lk_masque_config_add_ca_certs_pem(outer, pem_bytes, pem_len, &added) != LK_OK) {
    /* malformed bundle, or no certificate in it -- nothing was appended */
}
/* Only if the proxy is addressed by a name its certificate does not cover. */
lk_masque_config_set_server_name(outer, "proxy.internal", 14);

/* Requests through the proxy... */
lk_client_builder_set_masque_config(client_builder, outer);

/* ...and the health check, so a working proxy is not probed as dead. */
lk_proxy_pool_builder_set_health_check(pool_builder, "www.example.com", 15, 443,
                                      60000, 5000);
lk_proxy_pool_builder_set_masque_tunnel_probe(pool_builder, outer);

lk_masque_config_free(outer);
```

The probe setter and `lk_*_pool_builder_set_health_check` can be called in
either order; they are merged when the pool is built. Setting the probe with no
health check configured at all makes `lk_*_pool_builder_build` fail with
`LK_ERR_INVALID_CONFIG`, because a probe that can never run is a
misconfiguration rather than a default.

### `verify` is the last resort, not the private-CA answer

`lk_masque_config_set_verify(cfg, false)` skips **all** certificate
verification on the hop to the proxy. Reach for the anchors above first: the
private-CA deployment this switch is most often grabbed for is fully
expressible with them — add the CA, drop the OS store, override the certificate
name if needed — and that keeps the hop authenticated. What turning verification
off adds beyond that is only the ability to talk to a proxy you cannot identify
at all.

It is exposed because the false negative it rescues is not language-specific. A
certificate that cannot be made to verify — one naming a host that does not
resolve in this environment, say — leaves a C caller with the
blacklisted-healthy-proxy outcome and no way out of it, while a Rust caller has
`masque_verify(false)`. Withholding it here would not make anyone safer; it
would just make the C surface the one that cannot be unblocked.

Note what makes this hard to debug, and budget for it: an outer connection
terminated by a man in the middle looks exactly like a working one from every
side, and the C caller that flipped the switch, the binding that wrapped it and
the library that honoured it are three different codebases. The library logs
`masque.outer_certificate_verification_disabled` once per outer configuration so
the decision is at least visible in a trace. It is independent of
`lk_client_builder_set_verify`, which governs the hop to the origin — neither
implies the other.

`bind_addr`, `alpn` and `inbox_depth` are unexposed, for a different and much
weaker reason — no caller has asked. They can be added later without disturbing
anything.

### Without the `masque` feature

Every `lk_masque_config_*` symbol still exists, so the generated header and the
ABI do not change shape with a Cargo feature. `lk_masque_config_new` returns
`LK_ERR` and leaves the out-parameter `NULL`; since no handle can exist, the
setters and both consumers refuse too. A caller therefore learns the build
cannot do MASQUE at its first call, rather than after wiring up a configuration
that would be silently ignored. This is the same stance
`lk_proxy_config_parse` takes on a `masque://` URL.

## Browser Presets

Pass a canonical preset name to `lk_client_builder_set_preset`:

| Family | Names | TLS/H2 | QUIC/H3 |
|---|---|---|---|
| Chrome | `chrome_131`, `chrome_144` through `chrome_155` | Yes | Requires `quic-h3` |
| Firefox | `firefox_133`, `firefox_147`, `firefox_156` | Yes | Not provided |
| Safari | `safari_18`, `safari_26` | Yes | Not provided |

Use `lk_preset_list_json` to discover names in the loaded library and
`lk_preset_get_detail_json` to inspect a canonical name. The builder also accepts
`default` as an alias for `chrome_155` and `safari_26_2` for `safari_26`; the list
and detail APIs use canonical names.

`lk_client_new_default` and a builder with no explicit preset also select
`chrome_155`. Use the explicit `chrome_144` name to retain the previous default.

Chrome 154's H3 SETTINGS inherit the Chrome 153 baseline. Firefox 156's TLS/H2
fields were captured directly; its preset has no QUIC/H3 configuration even when
the library is built with `quic-h3`. See the
[support and verification matrix](../docs/reference/presets.md).

`chrome_155` directly verifies the Windows 155.0.8059.40 TLS/H2/QUIC fields
and H3 SETTINGS using passive public captures, including an H3 HTTP 200 response.

## Fingerprint Randomization

`lk_client_builder_set_randomize(builder, mode, layers)` selects how much of the
emitted fingerprint varies:

| `lk_randomize_mode_t` | Effect | Requires |
|---|---|---|
| `LK_RANDOMIZE_OFF` | the preset's fingerprint as-is | — |
| `LK_RANDOMIZE_EXTENSION_ORDER` | per-connection TLS extension-order jitter (still a real browser; drifts JA3, not JA4) | — |
| `LK_RANDOMIZE_RECOMBINE` | per-session synthetic identity recombined from the real-browser corpus | `synthetic-fp` |
| `LK_RANDOMIZE_FULL` | recombine **plus** out-of-corpus H2/QUIC values (widest divergence) | `synthetic-fp` |

`layers` is a bitmask applied to the synthetic modes only —
`LK_FP_LAYER_TLS | LK_FP_LAYER_H2 | LK_FP_LAYER_QUIC`; `0` means all layers (the
safe default). Unselected layers keep the client's real preset.

The synthetic modes (`RECOMBINE` / `FULL`) require building `lkrequest-ffi` with
the **`synthetic-fp`** feature (and **`quic-h3`** for the QUIC layer); without it
the setter returns an error rather than silently doing nothing. They emit
fingerprints that match **no** real browser — use only against negative-model
(blocklist) targets, never an allowlist.

```c
lk_client_builder_t *b = lk_client_builder_new();
lk_client_builder_set_preset(b, "chrome_154");

/* Tier 1 — real-browser per-connection jitter (always available): */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_EXTENSION_ORDER, 0);

/* Tier 3a — fresh synthetic identity per session, all layers (synthetic-fp): */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_RECOMBINE, 0);

/* Or synthesize only TLS, keeping the real H2/H3 preset: */
lk_client_builder_set_randomize(b, LK_RANDOMIZE_RECOMBINE, LK_FP_LAYER_TLS);
```

## Cookie Attributes

`lk_session_get_cookies_with_attrs_json(session, url, url_len, &json, &len, &err)`
returns unexpired cookies matching the URL, ordered by longest path and then
creation time. `lk_session_get_all_cookies_json(session, &json, &len, &err)`
returns all unexpired cookies across domains and paths, oldest first, including
Secure and HttpOnly cookies. Distinct cookies with the same name remain separate
array entries.

Each entry has `name`, `value`, `domain`, `host_only`, `path`, `secure`,
`http_only`, `same_site`, and `expires_unix`. Optional fields are JSON `null`;
`same_site` is `"Strict"`, `"Lax"`, `"None"`, or null. `expires_unix` is an
integer Unix timestamp in seconds, or null for a session cookie.

Both output parameters are required. The JSON is UTF-8 and NUL-terminated;
`len` excludes the terminator. Empty results are `[]`. The URL-filtered reader
also returns `[]` for an invalid URL, matching Rust. Invalid handles, pointer
arguments or UTF-8 produce `LK_ERR` with provided outputs reset to NULL/0.

The session handle owns the buffers: do not free them. A buffer remains valid
until its query is repeated, an explicit cookie setter/removal/clear runs, or
the handle is freed. Different queries and the legacy name/value reader have
separate cached buffers. Copy the result before an invalidating call and
synchronize reads with such calls when sharing a handle between threads.

```c
const char *json = NULL;
size_t len = 0;
lk_error_t *err = NULL;
if (lk_session_get_all_cookies_json(session, &json, &len, &err) == LK_OK) {
    /* Parse or copy the len bytes before another invalidating cookie call. */
}
if (err != NULL) {
    lk_error_free(err);
}
```

`lk_session_get_cookies_json` retains its original name/value-only schema.
Attribute export does not add attribute import: the current attribute setter
supports path/domain/Secure/HttpOnly, but not SameSite or expiry.

## ABI Notes

Important integration rules:

- All exported objects are opaque handles and must be released with their matching `free` function.
- `Client`, `Session`, and `Op` are shareable handles.
- `Request` and `StreamingResponse` are single-owner handles and must not be driven concurrently.
- Borrowed output pointers are owned by the handle that produced them.
- Borrowed chunk pointers from streaming reads are invalidated by the next mutating stream read, close, or free.
- String-returning `const char*` JSON getters are NUL-terminated.
- `lk_session_get_cookie()` returns a borrowed pointer backed by `SessionHandle` cache; it remains valid until a later cookie getter/mutator on that session or `lk_session_free()`.

There is one naming deviation from the original v2 draft:

- Session-local connection pool APIs are exported as `lk_session_connection_pool_stats` and `lk_session_connection_pool_clear`

This avoids ABI name collision with `lk_session_pool_t`.

## Runtime Model

`lkrequest-ffi` uses an internal global Tokio runtime.

Bindings do not need to provide:

- Tokio runtime handles
- wakers
- event-loop callbacks

Operations that create async work internally, including `ProxyPool` / `SessionPool` build and bad-marking paths, are routed back into the library runtime inside the facade.

## Recommended Verification

Before changing exported ABI or handle semantics, run:

```bash
cargo fmt --all
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

If the header changed:

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

`build.rs` already does this during normal Rust builds; the command above is only the manual fallback.

## Test Layout

Current integration tests are organized by responsibility:

- `tests/request_api_basics.rs`
  - ABI smoke
  - sync request/response basics
  - async op basics
- `tests/streaming_diagnostics_and_configuration.rs`
  - streaming sync/async
  - decoded streaming
  - diagnostics
  - builder configuration coverage
- `tests/ffi_contract_edge_cases.rs`
  - single-consume guarantees
  - wrong `take_*` API behavior
  - header lookup edge cases
  - debug-registry stale handle checks
- `tests/v2_capabilities_smoke.rs`
  - Response/Session v2 getters
  - Multipart
  - ProxyPool / SessionPool
  - DNS builder extensions
  - logging callback

C ABI smoke test:

- `tests/c_smoke.c`

## Windows C Smoke Example

```powershell
$env:PATH='D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Misc\tools\cygwin\bin\x86_64-w64-mingw32-gcc.exe' `
  -I lkrequest-ffi\include `
  -o target\debug\c_smoke.exe `
  lkrequest-ffi\tests\c_smoke.c `
  target\debug\lkrequest_ffi.dll.lib

$env:PATH='D:\Project\lkrequest\target\debug;D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Project\lkrequest\target\debug\c_smoke.exe'
```

## Tracked References

- `lkrequest-ffi/Cargo.toml`
- `lkrequest-ffi/cbindgen.toml`
- `lkrequest-ffi/src/`
- `lkrequest-ffi/tests/`
