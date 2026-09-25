# Changelog

All important changes to this project will be documented in this file.



## Unreleased

### Features

- Add Rust `ClientBuilder::ip_family(IpFamily::{Any, Ipv4, Ipv6})` for local
  TCP/QUIC candidate filtering, with explicit address-family errors that do not
  trigger proxy-to-direct fallback. Add `connect_to(host, port, address)` to
  override a dial target while preserving the origin's TLS and HTTP identity,
  including through HTTP CONNECT. The family restriction is local-only:
  DNS/DoH query transport and proxy-resolved target addresses are not constrained.
  A remote-DNS proxy can still connect to IPv6 targets with `Ipv4` selected;
  `connect_to` is an optional caller-maintained IP mapping for those targets.
  Python and C ABI configuration are unchanged.

- **Chrome 154 fingerprint preset** — Adds `chrome_154` across TLS, H2,
  QUIC/H3, the high-level Rust preset, FFI, synthesis, profile collection, and
  fingerprint regression fixtures. Public Cloudflare captures from Chrome
  154.0.8037.58 on Windows verify that TCP TLS, H2, QUIC TLS, QUIC transport
  parameters, and Chromium Initial packetization retain Chrome 153's stable
  shape. H3 application settings retain the completed Chrome 153 navigation
  baseline because the current public capture path received no QUIC response.

- **Firefox 156 fingerprint preset** — Adds capture-verified `firefox_156`
  TLS and H2 profiles to the Rust and FFI APIs. Firefox 156.0.1 removes two
  ECDSA CBC suites and both FFDHE groups from Firefox 147 and switches ECH
  GREASE to AES-128-GCM; its H2 fingerprint remains unchanged. QUIC/H3 stays
  disabled because the current stack cannot yet reproduce several observed
  Firefox transport and Initial-packet fields exactly.

### Fixes

- Preserve MASQUE tunnel errors and retry eligibility after temporary datagram
  capacity failures in streaming requests and preconnect, matching buffered
  requests. Streaming requests no longer attempt TCP fallback through a MASQUE
  proxy. Fix IPv4 target selection in the FFI MASQUE relay fixture and stabilize
  the PMTU regression tests with a bounded probe gate.

## lkrequest 0.2.3

### Upgrade from 0.2.2

This release contains Rust source-level breaking changes despite its patch
version. Cargo may select it automatically for a `^0.2.2` requirement, so
downstream crates using the APIs below should update their source before
upgrading:

- Replace `ProxyConfig { scheme, auth, chain }` literals with
  `ProxyConfig::new(scheme)` or `ProxyConfig::parse(url)`, then set credentials
  and chain through the existing fields or setters. `ProxyConfig` now has new
  authentication fields and is `#[non_exhaustive]`.
- Replace `HealthCheckConfig { ..., ..Default::default() }` literals with
  `let mut health = HealthCheckConfig::default();` followed by field assignments.
  It is now `#[non_exhaustive]`.
- Complete `H3Profile`, `QuicTransportParams`, and `QuicPacketizationProfile`
  literals need the new `chromium_grease`, `randomize_grease_shape`, and
  `initial_packet_chaos` fields, respectively. Set them to `false` to retain
  the previous custom-profile behavior. Old serialized profiles still load.
- With the new `masque` feature enabled, exhaustive `ProxyScheme` matches need
  a `Masque` arm. The feature is experimental and off by default.

### Features

- **MASQUE CONNECT-UDP proxies (experimental)** — A `masque://` proxy now carries a
  QUIC/HTTP-3 connection to the target over an outer HTTP/3 connection: RFC
  9298 (Proxying UDP in HTTP) on top of RFC 9297 (HTTP Datagrams and the
  Capsule Protocol). It is the UDP counterpart of the existing SOCKS5 UDP
  ASSOCIATE path. Behind the new `masque` feature, which is off by default and
  implies `quic-h3`. MASQUE-specific APIs and proxy interoperability may change
  while validation against independent proxy implementations is pending;
  without the feature a `masque://` URL is rejected by
  `ProxyConfig::parse` with an error naming the feature, rather than parsed
  into a configuration every request would fail on. The proxy must support
  HTTP/3 *and* HTTP Datagrams; the port defaults to 443, and the target is
  encoded in the CONNECT-UDP path, so the route resolves DNS remotely like
  `socks5h`.

  The wire format and the tunnel state machine live in a new crate,
  **`lkmasque`**: varint and two-layer HTTP Datagram coding, a
  `QuarterStreamId` newtype, minimal Capsule framing, URI Template expansion,
  the two independent payload size limits, and a `TunnelTable` that
  demultiplexes connection-level datagrams. It performs no I/O, reads no clock
  and depends only on `thiserror`, so it is usable on its own — from another
  QUIC stack, to implement a MASQUE endpoint, or to debug framing. The I/O
  bridge stays in `lkrequest` (`proxy::masque`), because it can only be built
  against this workspace's patched `h3` and `quinn` forks; it presents each
  tunnel to the inner QUIC stack as a `quinn::AsyncUdpSocket`, so the inner
  connection never learns it is tunneled.

  One outer connection per (session, proxy identity) multiplexes as many
  tunnels as the session needs, and that sharing stops at the session boundary
  so a proxy cannot correlate identities the client separated on purpose.
  `ClientBuilder::masque` takes the whole `MasqueOuterConfig` (bind address,
  SNI, trust anchors, certificate verification, ALPN);
  `masque_tunnel_idle_timeout` (default 120s, `None`
  disables idle reclamation) and `masque_max_idle_tunnels` (default 256, `0`
  removes the cap) are the two tunnel-lifecycle knobs.

  The outer hop's certificate verification is configured separately from the
  origin's, and never inherits from it: a debugging CA or a relaxed `verify`
  meant for one hop must not silently become the trust decision for the other.
  `MasqueOuterConfig::add_ca_certs_pem` loads a private CA from the PEM bundle
  it is actually distributed as (`extra_roots` is DER), reporting a malformed
  bundle — or one holding no certificate — as `Error::InvalidConfig` rather
  than leaving the trust store silently unchanged. `MasqueOuterConfig::verify`
  (default `true`) is the development-only escape hatch that skips outer
  certificate verification entirely; with it off, anything answering on the
  proxy's address terminates the outer TLS connection and sees every tunnel's
  CONNECT-UDP target, so that hop is fully open to a man in the middle.
  `ClientBuilder` mirrors the cluster field by field —
  `masque_add_ca_certs_pem` (fallible), `masque_add_ca_cert_der`,
  `masque_use_native_certs`, `masque_server_name`, `masque_verify` — so
  changing one setting no longer means constructing the whole struct. The
  CONNECT-UDP health-check probe takes its trust anchors from the same
  configuration.

  Three known limitations:

  1. **DNS-discovered ECH configs and H3 hints are unavailable on a MASQUE
     route.** It is a remote-DNS route, so no local HTTPS/SVCB query is made
     for the target — the same reason as `socks5h`, and for the same purpose:
     the query would leak the target hostname out-of-band from the proxy.
     Explicitly configured ECH (`ClientBuilder::ech_config`,
     `SessionBuilder::ech_config`) still applies.
  2. **The outer connection is not a browser fingerprint.** It uses quinn's own
     rustls defaults with ALPN `h3`, so an observer on the path can tell it is
     not a browser. The inner fingerprint the origin sees is unaffected.
  3. **UDP only.** With a MASQUE proxy configured, HTTP/1.1 and HTTP/2 requests
     (including cleartext `http://` targets) fail with an explicit proxy
     protocol error naming HTTP CONNECT or SOCKS5 as the alternative — never a
     silent direct connection. A failed tunnel does not fall back to a direct
     connection either, even with `proxy_fallback_direct` enabled, because that
     would leak the source address the tunnel exists to hide.

  Tunnel failures are classified and quarantined: 401/407 as
  `ProxyErrorKind::AuthenticationFailed`, other 4xx/5xx as
  `ProxyErrorKind::TunnelRefused { status_code }`. A 4xx refusal is recorded
  per-origin (RFC 9298 §3.1 has the proxy evaluate the target, so a `403` means
  "not this destination" from a working proxy); everything else quarantines the
  whole route as `BrokenReason::MasqueTunnelUnavailable`, kept distinct from
  SOCKS5's `ProxyUdpUnavailable`. MASQUE is rejected as a proxychain hop:
  nested tunnels shrink the usable MTU, which is already bounded by the outer
  datagram limit.

- **`ProxyCredential`: proxy credentials beyond username/password** — Proxy
  authentication is now an enum. `ProxyCredential::UserPass` is what the URL
  form and `ProxyConfig::auth` have always produced (`Basic` on header proxies,
  the RFC 1929 sub-negotiation on SOCKS5). `ProxyCredential::Http { scheme,
  credentials }`, set with `ProxyConfig::with_http_auth`, carries a static HTTP
  auth-scheme plus already-encoded credentials — `Preshared`, `PrivateToken`,
  `Bearer` and the like. `ProxyCredential::Custom`, set with
  `with_custom_auth`, takes a `ProxyAuthenticator` that computes the
  authorization value per attempt; it is Rust-only, because a trait object
  cannot cross the C ABI.

  `ProxyAuthHeader` selects the field name, because there is no interoperable
  answer: RFC 9298 does not specify proxy authentication at all, several
  deployments read `Proxy-Authorization` (the default) and masque-go's
  documented example and RFC 9484 §11 use `Authorization`. `ProxyConfig::auth`
  keeps working unchanged and is now sugar for `UserPass`; setting both `auth`
  and `credential` is rejected by `validate`, as is a header credential on a
  SOCKS5 proxy, which has no way to carry one.

- **Opt-in CONNECT-UDP health-check probe** — `HealthCheckConfig` gained
  `tunnel_probe` and `masque_outer_config` under the `masque` feature. The
  ordinary check establishes a TCP connection and calls the proxy alive, which
  for a MASQUE proxy proves nothing: a reachable TCP port says nothing about
  HTTP Datagram support, `connect-udp` acceptance, or the credentials. So by
  default MASQUE proxies are skipped by the active checker entirely — neither
  credited nor blamed, and never blacklisted by it. With `tunnel_probe` on
  *and* an outer config supplied, each one gets a real probe: outer HTTP/3
  connection, one CONNECT-UDP tunnel to the health-check target, verified ready
  (2xx, and not in violation of RFC 9297 §3.2), then closed. `tunnel_probe` on with
  `masque_outer_config` left `None` skips too, with a `warn`: probing a proxy
  fronted by a private CA against guessed trust anchors would fail the
  handshake and blacklist a healthy proxy, and a false negative there is worse
  than not checking at all.

- **MASQUE outer configuration on the C ABI** — `lkrequest-ffi` gained
  `lk_masque_config_t`, an opaque handle built with `lk_masque_config_new` and
  released with `lk_masque_config_free`, plus
  `lk_masque_config_add_ca_certs_pem` (a bundle, reporting how many
  certificates it loaded), `lk_masque_config_add_ca_cert_der`,
  `lk_masque_config_set_use_native_certs`, `lk_masque_config_set_verify`,
  `lk_masque_config_set_server_name`,
  `lk_masque_config_set_tunnel_idle_timeout` and
  `lk_masque_config_set_max_idle_tunnels`. Two entry points consume it —
  `lk_client_builder_set_masque_config` for the request path, and
  `lk_proxy_pool_builder_set_masque_tunnel_probe` /
  `lk_session_pool_builder_set_masque_tunnel_probe` for the health check's
  CONNECT-UDP probe — and both copy the settings, so one handle can feed both
  and is freed once.

  This fixes the C side of the false negative above: a MASQUE proxy fronted by
  a private CA could not be named as trusted from C at all, so the probe
  verified it against the operating system's store, failed the handshake and
  blacklisted a working proxy. The probe setter is order-independent with
  respect to `set_health_check`; configuring it with no health check at all is
  reported by `build` as `LK_ERR_INVALID_CONFIG` rather than silently never
  probing.

  `lk_masque_config_set_verify` is the last resort rather than the private-CA
  answer — the anchors above are, and they keep the hop authenticated. It
  exists because the false negative is not language-specific: a C caller facing
  a certificate that cannot be made to verify at all would otherwise have only
  the blacklisted-healthy-proxy outcome and no way out of it, while a Rust
  caller has `masque_verify(false)`. It carries the same risk as the Rust
  switch, and is independent of `lk_client_builder_set_verify`, which governs
  the hop to the origin.

  All of these symbols require the `masque` feature; without it they exist but
  refuse, so the header does not change shape with a Cargo feature.

- **Readable cookie attributes** — Added `CookieInfo` plus
  `Session::get_cookies_with_attrs(url)` and `Session::get_all_cookies()`, and
  the same two on the blocking `Session`. `get_cookies` returns `(name, value)`
  pairs, which cannot distinguish two cookies that share a name at different
  paths: the jar holds both, and only the attributes say which is which. The
  new view carries `name`, `value`, `domain`, `host_only`, `path`, `secure`,
  `http_only`, `same_site` and `expires_unix`, which is what a caller needs to
  hand a jar to a browser automation context, to persist a login and tell
  session cookies from persistent ones, and to work out why a cookie the jar
  holds was not sent. `get_cookies_with_attrs` is scoped to a URL like
  `get_cookies`; `get_all_cookies` spans every domain and skips expired
  entries, which is the view to persist.

  `CookieInfo` owns every field and reports `expires_unix` as a Unix timestamp
  rather than an `OffsetDateTime`, so the cookie store's types stay out of the
  public API and the shape maps directly onto the language bindings.

  `get_all_cookies` lists cookies oldest first, so setting them into a fresh
  session in that order reproduces the same `Cookie` headers.

- **Chrome 153 TLS / H2 / QUIC preset** — Captured from Chrome 153.0.8010.37
  on Windows with Wireshark against Cloudflare on September 15, 2026. TCP TLS
  retains signature-algorithm GREASE and reduces the shuffled `0xca34`
  trust-anchor identifier set from 32 to 28 values, removing `d6790902`,
  `d6790903`, `d6790909`, and `d679090e`. H2 retains the verified Chrome 152
  SETTINGS, connection window, pseudo-header order, and initial HEADERS
  priority. QUIC retains the classic nine signature algorithms, shuffled
  ClientHello extensions, and the 28 trust-anchor identifiers. A completed H3
  navigation returned HTTP 200 with SETTINGS `1=65536`, `6=262144`, `7=100`,
  and `51=1`, plus GREASE and navigation priority `u=0, i`. The reserved
  transport-parameter payload remains randomized.
- **Chromium QUIC wire generation** — Chrome 146 and 150–153 presets now use
  Chromium's generation rules for three randomized parts of the H3/QUIC wire
  image. H3 sends a random reserved SETTINGS id/value, a 0–3 byte
  control-stream GREASE frame, and no request-stream GREASE
  (`H3Profile::chromium_grease`). Reserved transport parameters use the full
  62-bit GREASE id space with 0–15 byte payloads and a randomized GREASE
  version position. Client Initials split, pad, and shuffle CRYPTO data with
  interleaved PING/PADDING per connection
  (`QuicPacketizationProfile::initial_packet_chaos`), including across loss,
  Retry, and 0-RTT. All three new profile fields default to `false`, so custom and
  previously serialized profiles keep their existing behavior. The patches live
  in the `deps/h3` and `deps/quinn` forks on `lkrequest-patches`.

### Breaking changes

- **Custom H3/QUIC profile struct literals need new fields** — `H3Profile`,
  `QuicTransportParams`, and `QuicPacketizationProfile` now have
  `chromium_grease`, `randomize_grease_shape`, and `initial_packet_chaos`,
  respectively. External code that constructs these structs with complete
  literals must add the corresponding field (usually `false`). Existing
  serialized profiles still deserialize because all three fields have Serde
  defaults; presets supply their own values. Code that starts with a preset or
  `QuicPacketizationProfile::default()` and mutates fields is unaffected.

- **`ProxyConfig` is `#[non_exhaustive]`** — A struct literal no longer
  compiles outside the crate. Build one with `ProxyConfig::parse` (a URL),
  `ProxyConfig::parse_chain` (a proxychain) or the new
  `ProxyConfig::new(scheme)` (a `ProxyScheme` already in hand), then layer the
  rest on with the chaining setters (`with_user_pass`, `with_http_auth`,
  `with_custom_auth`, `with_auth_header`, `through`). There is deliberately no
  `Default`: every `ProxyScheme` carries a host and a port, and no address
  could stand in for them without inventing one. The fields stay public and
  readable/writable — sealing applies only to literals, so `config.auth = …`
  style mutation keeps working. Proxy authentication is still an open-ended
  area (`credential` and `auth_header` were themselves added here), and this
  keeps the next field from being a breaking change for every downstream crate.

  Enabling `masque` also adds `ProxyScheme::Masque`; exhaustive matches on
  `ProxyScheme` need another arm when that feature is active.

- **`HealthCheckConfig` is `#[non_exhaustive]`** — A struct literal no longer
  compiles outside the crate, and `..Default::default()` does not rescue it
  either. Build one from `HealthCheckConfig::default()` and assign the fields
  that matter, e.g. `health.interval = …; health.target_host = …;`.

  Its MASQUE fields exist only with the `masque` feature, so a literal would
  otherwise have to name a different set of fields depending on which features
  the final binary happens to turn on — something a downstream crate cannot
  control. `BadProxyConfig` is unaffected.

- **`MasqueOuterConfig` is `#[non_exhaustive]`** — A struct literal no longer
  compiles outside the crate, `..Default::default()` included. Build one from
  `MasqueOuterConfig::default()` and assign the fields that matter, or use the
  per-field `ClientBuilder::masque_*` setters, which need no struct at all.

  This is the growing end of the MASQUE surface, and it is sealed while that is
  still free: `verify` arrived after the rest, the C ABI entry points below
  want more, and challenge-based proxy authentication will want more again.
  MASQUE ships in this release, so no downstream literal exists to break. As
  with the two above, the fields stay public and writable — only the literal
  form is sealed.

### Fixes

- **MASQUE response validation followed the wrong half of the specification** —
  An RFC compliance audit found the check in `TunnelDriver::feed_response`
  inverted: it enforced a SHOULD as fatal while ignoring the two MUSTs beside
  it.

  A 2xx response that omitted `capsule-protocol: ?1` failed the tunnel and,
  through the route quarantine, blacklisted the proxy. But RFC 9298 §3.5
  imports the requirements of **RFC 9297 §3.2**, and that header is not among
  them — its own requirement is in RFC 9297 §3.4 and reads "endpoints SHOULD
  send the Capsule-Protocol header field to simplify intermediary processing",
  while §3.2 notes an intermediary may instead rely on "understanding the
  chosen HTTP Upgrade token". For a 2xx answer to `connect-udp` the Capsule
  Protocol is already in force. So the client was refusing proxies that were
  within the specification. It no longer does: the observation is available as
  `TunnelDriver::capsule_protocol_header` and logged as
  `masque.capsule_protocol_header_absent` / `_not_true` / `_repeated`, and
  `TunnelError::CapsuleProtocolNotNegotiated` is gone, since nothing fails for
  that reason any more. A repeated field is now reported as repeated rather
  than resolved to its last value, which RFC 9297 §3.4 calls out by name (the
  field's type becomes a List and "MUST be handled as if the field were not
  present") — with `?0` followed by `?1`, the old loop reported a negotiation
  the field never expressed.

  What §3.2 does require was unchecked and now is, as
  `TunnelError::MalformedResponse`: status 204, 205 and 206 "MUST NOT be sent
  on responses that use the Capsule Protocol", and neither may the message
  carry `content-length`, `content-type` or `transfer-encoding`; a receiver
  seeing either "MUST treat the HTTP message as malformed". The realistic case
  is `content-length: 0` on a bodyless 200, which HTTP frameworks add on their
  own. Accepting it meant parsing the data stream of a message that declares
  HTTP content as capsules — failing later with an error that blamed the
  capsule framing, or swallowing content as if it were capsules. The error now
  names the offending field.

- **An over-large MASQUE capsule killed the tunnel instead of being skipped** —
  RFC 9297 §3.2 requires an unknown Capsule Type be "silently drop[ped] and
  skip[ped] over ... to parse the next Capsule", and RFC 9298 §5 asks that an
  over-large DATAGRAM capsule be discarded "without buffering the capsule
  contents". `TunnelDriver` did the opposite: it accumulated the whole Value
  and, once the residue passed `max_stream_buffer`, failed the tunnel — which
  reset the request stream, killed the inner QUIC connection and quarantined
  the route, over one capsule it had no use for. The same §3.2 warns against
  that accumulation directly ("This approach SHOULD be avoided because it can
  consume flow control in underlying layers").

  `CapsuleParser::peek_header` now reads a capsule's Type and Length without
  its Value, and the driver steps over anything declaring more than
  `max_stream_buffer`, counting it in
  `TunnelStats::capsules_skipped_over_limit`. Buffering is bounded by
  construction — the limit plus one capsule header — so
  `TunnelError::CapsuleBufferOverflow` is removed rather than left unreachable.
  A stream that ends mid-skip is still a truncated capsule and still malformed
  under §3.3.

  Two things this also fixes. The old check looked at leftover bytes rather
  than at the declared length, so the same byte sequence passed in one
  `feed_stream` call and failed across several — a protocol outcome decided by
  how the peer chopped up its writes. And `DEFAULT_MAX_STREAM_BUFFER` rises
  from 64 KiB to 128 KiB: RFC 9000 §16 permits non-minimal varint encodings, so
  a *legal* DATAGRAM capsule carrying the largest permitted UDP payload can
  have a 65535-byte Value, which the old ceiling cleared by 9 bytes and would
  now have skipped.

- **Chrome cookie order** — The session jar iterated `cookie_store`'s hash
  maps, so the `Cookie` header order was arbitrary and differed between
  sessions, and `get_cookie` / `get_cookie_values` did not reliably return the
  longest-path match first as documented. The jar now records creation order
  and sorts like Chrome's `CookieSorter`: longer paths first, then older
  cookies first. As in Chrome, re-setting a cookie with the same value keeps
  its creation time, and a new value makes it a new cookie. A local capture of
  Chrome 153 sending the same `Set-Cookie` sequence produced the identical
  `Cookie` header. An explicit `cookie_order` still takes precedence; cookies
  it does not name now follow this order instead of an arbitrary one.

### Deprecations

- **`h2-native` is scheduled for complete removal in 0.3.0** — it remains a
  no-op compatibility alias during the 0.2.x line. HTTP/2 always uses `lkh2`;
  applications that explicitly enable `features = ["h2-native"]` should remove
  that entry now. The alias will be removed from both `lkrequest` and `lkh2`.

### 弃用

- **`h2-native` 将在 0.3.0 完全删除** — 该名称在 0.2.x 中仅作为 no-op 兼容
  别名保留，HTTP/2 始终使用 `lkh2`。显式配置
  `features = ["h2-native"]` 的应用应立即移除该项；`0.3.0` 会同时从
  `lkrequest` 和 `lkh2` 删除此别名。



## lkrequest 0.2.2

This patch release adds the Chrome 152 preset and hardens protocol correctness, browser-session behavior, and compatibility after **v0.2.1**.

### Features

- **Chrome 152 TLS / H2 / QUIC preset** — Captured from Chrome
  152.0.7977.65 on Windows against public Cloudflare endpoints on August 28,
  2026. TCP TLS prepends an independently randomized GREASE code point to
  `signature_algorithms`, ahead of the ML-DSA algorithms, and adds
  Chromium/BoringSSL's `0xca34` trust-anchor identifier vector with
  per-ClientHello order randomization. H2 retains Chrome 151's SETTINGS,
  connection window, pseudo-header order, and priority shape. QUIC retains the
  Chrome 151 signature and transport baseline but removes the no-longer-sent
  `google_initial_rtt` parameter (`0x3127`). The capture established the QUIC
  ClientHello and client transport parameters but not a complete H3 SETTINGS
  exchange, so H3 intentionally retains the latest verified Chrome baseline.

### Fixes

- **Chrome 152 signature-algorithm GREASE parity** — The initial preset omitted
  the leading GREASE slot that real Chrome 152 sends before `0x0904`, `0x0905`,
  and `0x0906`, causing `peetprint_hash` to diverge even though JA3/JA3N, JA4,
  and the HTTP/2 Akamai fingerprint still matched. `lktls` now models a distinct
  per-connection signature-algorithm GREASE seed rather than reusing the cipher
  GREASE value, and `fpverify` tokenizes that random value in place so regression
  goldens preserve the required list position.
- **ECH rejection now aborts instead of returning an unprotected connection** —
  when a server did not accept Encrypted ClientHello, `lktls` logged the fact and
  carried on: it installed application traffic keys and handed the caller a
  connection whose true server name had never been protected, so the request ECH
  existed to hide went out in the clear. RFC 9849 §6.1.6 allows the outer
  handshake only to authenticate the config's `public_name` and collect
  `retry_configs`. Both the TCP and QUIC paths now abort there, before any
  traffic keys or session-ticket context exist, and TCP sends an `ech_required`
  alert (121, newly modelled) after its client Finished. Certificate
  verification on the rejection path targets the `public_name` — the identity
  the server actually presents — instead of failing against a name it never
  claimed. GREASE ECH is unaffected: it is not an ECH offer, so a server
  ignoring it rejects nothing.
- **ECH rejection is retried once with the server's `retry_configs`** — ECH is
  enabled automatically from DNS HTTPS records, so aborting alone would turn a
  routine ECH key rotation into a hard failure for ordinary traffic. The session
  now redials once using the configs the server supplied, as a browser does.
  Retrying *without* ECH is deliberately not a fallback: it would leak the very
  name ECH protects.

- **Alternative services no longer supply the TLS identity** — an Alt-Svc entry
  or HTTPS RR names *where* to send packets, but the endpoint must still prove it
  may serve the origin (RFC 7838 §3.1, RFC 9460 §2.3). The advertised host was
  used as the SNI and certificate name, so the alternative authenticated as
  itself — and conforming deployments failed outright, since an HTTPS RR
  `TargetName` is typically a CDN's internal name serving the origin's
  certificate. The dial target still follows the advertisement.
- **Status-code retries are gated on replay safety** — the error-retry path
  checked `retry_is_replay_safe`, the status path checked nothing, so a `POST`
  answered with `502` was sent twice. Since the server answered, the request
  certainly arrived; a non-idempotent method is now replayed only on a status
  that says it was *not applied* — `429` and `503`. `502`, `504` and the
  Cloudflare `520`–`530` range are ambiguous about whether the origin already
  processed the request and are returned to the caller instead. Safe methods and
  an explicit `Idempotency::Idempotent` are unaffected; see
  `Session::retry_policy` for how to restore the old behaviour per request.
- **WebSocket handshake responses are validated** — only the `101` status was
  checked; a wrong or missing `Sec-WebSocket-Accept` merely logged a warning.
  RFC 6455 §4.1 requires failing the connection on that, on a missing or wrong
  `Upgrade`/`Connection`, and on any extension or subprotocol the client did not
  offer. All are enforced now. This also uncovered that `Sec-WebSocket-Accept`
  was computed with a GUID that is not the one RFC 6455 §1.3 specifies, so the
  token never matched a conforming server — invisible while the check only
  warned, and while the local test server had independently invented a third
  value. Both now use the specified GUID, pinned by the §1.3 test vector.
- **TLS post-handshake message framing** — post-handshake messages follow the
  same framing as the handshake itself (RFC 8446 §5.1): several may be coalesced
  into one record and one may span several records. Each record was treated as
  exactly one message, so a `KeyUpdate` sharing a record with a
  `NewSessionTicket` was silently dropped — the read keys were never rotated and
  every subsequent record failed to decrypt — and coalesced tickets past the
  first were lost. Decrypted handshake bytes are now buffered and only complete
  messages dispatched, mirroring the handshake-time reassembly.
- **HTTP/2 GOAWAY with `NO_ERROR`** — a graceful shutdown (which Google and
  Cloudflare send routinely for connection turnover) carries `NO_ERROR` and so
  set no connection error, while the draining check keyed off "has error". The
  driver kept opening streams the peer had already promised to refuse (RFC 9113
  §6.8). Draining is now keyed off GOAWAY receipt itself, so queued requests
  fail over to a fresh connection; the GOAWAY `last_stream_id` is exposed for
  callers that need to tell processed from unprocessed streams.
- **`304 Not Modified` no longer treated as a redirect** — every 3xx was
  classified as a redirect, so a conditional request answered with `304` (and
  likewise `300`/`305`/`306`) reached the `Location` lookup and failed with
  `redirect response missing Location header`. Only `301`/`302`/`303`/`307`/`308`
  are followed now; the rest are returned to the caller as-is (RFC 9110 §15.4).
- **`Content-Encoding: deflate` accepts the zlib form** — RFC 9110 §8.4.1.2
  defines `deflate` as the zlib format (RFC 1950), but only a bare RFC 1951
  stream was decodable, so spec-conforming servers failed outright. Both the
  one-shot and streaming paths now sniff the zlib header and select the matching
  decoder; the streaming path holds back the first bytes until the format is
  decidable.
- **`multipart/form-data` no longer announces the library** — the boundary was
  built as `----lkrequest{hex}`, so the crate name went out in the
  `Content-Type` of every upload and a single server-side regex identified it,
  whatever the TLS and HTTP/2 fingerprints said. It now matches what a real
  Chrome 151 emits, captured rather than guessed
  (`tests/b_layer_chrome_multipart.rs` drives a real browser at a local
  plaintext server): `----WebKitFormBoundary` followed by exactly 16
  alphanumerics. The random part is drawn by rejection sampling so the
  character distribution is uniform — `byte % 62` would over-weight the first
  eight letters, and a skewed distribution is itself a tell. **This changes the
  bytes on the wire.**
- **multipart field names and filenames are escaped the way Chrome escapes
  them** — they were interpolated into `Content-Disposition` verbatim, so a
  caller-supplied name containing CR or LF could terminate the header line
  (RFC 5322 §2.2) and append part headers, start an extra part, or forge the
  boundary. From the same capture: `"` becomes `%22`, CR and LF become `%0D`
  and `%0A`, and everything else — backslash, `;`, non-ASCII — goes out
  verbatim as UTF-8. One asymmetry no amount of reading the RFC would predict:
  a *field name* has its newlines normalised to CRLF first, so a lone CR and a
  lone LF both come out `%0D%0A`, while a *filename* is not normalised and a
  lone LF stays `%0A`. `Content-Type` has no quoted form to escape into, so a
  CR or LF there is rejected instead (Chrome discards the type entirely and
  sends `application/octet-stream`; an error is easier to debug than a silent
  substitution, and neither puts the bytes on the wire).
- **A TLS 1.2 `HelloRequest` is refused with a fatal alert instead of being
  ignored** — it was dropped silently, which no browser does, leaving a
  behavioural probe for any server willing to send one. BoringSSL's client
  default is `ssl_renegotiate_never`, which sends a **fatal**
  `no_renegotiation` and aborts; Chrome reaches the same state after the
  handshake unless the negotiated ALPN is in `renego_allowed_for_protos`, empty
  by default and never containing h2 (RFC 9113 §9.2.1 forbids renegotiation
  outright). Note the alert is fatal even though RFC 5246 §7.2.2 calls
  `no_renegotiation` a warning — that deviation is BoringSSL's, and matching
  the browser is the point. **Behaviour change:** such a connection now ends
  with `ConnectionAborted` where it previously carried on.
- **The handshake fails when the server picks something the client never
  offered** — a TLS 1.2 `named_curve`, a `ServerKeyExchange` signature
  algorithm, or a TLS 1.3 `CertificateVerify` scheme was only checked against
  what the implementation supports, never against what the ClientHello
  advertised. Completing a handshake on an unadvertised algorithm is a
  contradiction the server can see. Duplicate-extension detection also ran only
  on the HelloRetryRequest branch, and `rsa_pkcs1_*` is now rejected in
  `CertificateVerify` per RFC 8446 §4.4.3.
- **The peer's `record_size_limit` is honoured when sending (RFC 8449)** — the
  extension was advertised but never applied; records were always sliced at
  16384 bytes, so a peer that asked for smaller records got oversized ones.
- **TLS record layer hardened and session-ticket trust bounded** — plaintext
  handshake and alert records were still accepted after handshake keys were
  installed; an unknown record `content_type` was silently skipped where
  RFC 8446 §5.1 requires `unexpected_message`; TLS 1.2 resumption neither
  recorded nor checked the Extended Master Secret state (RFC 7627); and ticket
  lifetimes were unbounded, now capped at seven days. Post-handshake reader
  arming also uses the `record_size_limit` we advertised.
- **Unsolicited TLS 1.2 extensions are refused, and port-0 alternative services
  dropped** — the TLS 1.2 parser had no "did we offer this?" check, unlike the
  TLS 1.3 path. Separately, `h3=":0"` produced an alt-authority pointing at a
  port RFC 6335 §6 reserves and nothing listens on.
- **A connection that ends without `close_notify` is distinguishable from a
  clean shutdown** — both produced an identical EOF, so on a body delimited by
  connection close (RFC 9112 §6.3) a truncation was indistinguishable from a
  complete response. `TlsStream::received_close_notify()` now reports which
  happened, and `ClientBuilder::require_close_notify(true)` turns the ambiguous
  case into `UnexpectedEof`. **Off by default** — many production servers just
  drop the connection and browsers accept that. One part is unconditional: the
  read loop stops at `close_notify` instead of polling on, because RFC 8446
  §6.1 means anything arriving after it did not come from the peer, and those
  bytes were being appended to the response body.
- **HTTP/2 responses are validated rather than quietly repaired** — a
  `content-length` that disagreed with the DATA actually delivered was accepted
  (a response-length desync), headers that failed to parse were dropped, and a
  missing or malformed `:status` became `500`. Connection-specific fields
  (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Proxy-Connection`) are now
  rejected per RFC 9113 §8.2.2, pseudo-header rules are enforced, DATA is held
  to the same standard as HEADERS, and `101` is no longer treated as an interim
  status (HTTP/2 does not use it).
- **A malformed HTTP/2 response now resets the stream** — RFC 9113 §8.1.1 makes
  it a stream error of type PROTOCOL_ERROR, but nothing was written to the
  wire. Chromium's netlog runs `HTTP2_SESSION_RECV_INVALID_HEADER` →
  `HTTP2_SESSION_SEND_RST_STREAM`, so silence was the divergence, not the
  fidelity — and it let the server keep sending DATA on a stream already torn
  down, with that stream's flow-control window never returned.
- **The HTTP/2 connection state machine is tighter on peer protocol errors** —
  frames could be interleaved into a CONTINUATION sequence, stream-state checks
  on the HEADERS path were weaker than on DATA, every `SETTINGS` error mapped
  to PROTOCOL_ERROR where an `INITIAL_WINDOW_SIZE` overflow must be
  FLOW_CONTROL_ERROR, and a local connection error did not move the connection
  to a terminal state. Fixing the DATA path also closed a pre-existing
  connection-window leak: a frame arriving on a stream that could not receive
  consumed connection window that was never replenished.
- **DNS HTTPS/SVCB records are read as records, not merged field by field** —
  fields from same-priority records were mixed together, producing endpoint
  descriptions no server ever published; `AliasMode` was not followed;
  `mandatory` (key 0) and `no-default-alpn` (key 2) were silently dropped, so a
  client could connect with a protocol the endpoint had declared it does not
  speak. Alias chains are followed with loop detection and a hop cap.
- **Alternative services keep the bracketed IPv6 form and honour `persist`** —
  brackets were stripped at parse time while `Url::host_str()` keeps them, so a
  bare `2001:db8::1` reached the dialer and could not be used.
- **HTTPS-RR discovery issues one query per request instead of two** — protocol
  discovery and the TLS handshake's automatic ECH configuration each ran their
  own lookup. Beyond the extra round trip, the two answers could disagree: a
  rotated ECH key or a load-balanced resolver left the ECH config out of step
  with the endpoint the H3 decision was made against.
- **Draft HTTP/3 advertisements are ignored** — `select_h3` fell back to any
  `h3-*` token including `h3-29`, while Chrome 140+ accepts only `h3`.
- **QUIC early-data tickets, HTTP/3 SETTINGS and HTTP/3 ECH are validated** — a
  QUIC ticket's `max_early_data_size` was accepted whenever non-zero, where
  RFC 9001 §4.6.1 requires exactly `0xffffffff`; custom H3 profiles could emit
  reserved settings identifiers; and the H3 path was missing two of the three
  ECH configuration fallbacks the TCP path already had.
- **Redirects rewrite the method only where the spec says to** — `301`, `302`
  and `303` unconditionally became `GET`, so a `HEAD` request came back as a
  `GET`, which Chrome does not do. `303` still rewrites everything except
  `HEAD` (RFC 9110 §15.4.4).
- **Multi-layer `Content-Encoding` is decoded** — only the outermost coding was
  handled, so `gzip, br` was returned still compressed with a header claiming
  otherwise. Codings are now applied in reverse order, in both the one-shot and
  streaming paths.
- **Cookie name prefixes are enforced, and `Secure` cookies from plain HTTP are
  ignored** — `__Secure-` and `__Host-` carry security meaning only if the
  requirements are checked (RFC 6265bis §5.6), and a `Secure` cookie received
  over plain HTTP was stored regardless of its name.
- **HSTS is learned only from a secure transport, and never for IP literals** —
  a plaintext HTTP response could inject a `Strict-Transport-Security` policy
  into a session using `DynamicHsts` (RFC 6797 §8.1).
- **SOCKS5 sub-negotiation replies are validated, and any 2xx completes a
  CONNECT tunnel** — the username/password reply's version byte was never
  checked (RFC 1929), and only an exact `200` was accepted where RFC 9110
  §9.3.6 makes every 2xx a success.
- **Sessions are no longer capped at 64 physical connections by default** —
  the implicit ceiling caused unrelated high-concurrency workloads to fail
  with `session connection limit reached`. The default is now unbounded;
  callers that need a hard budget can still set `max_connections_per_session`
  or `SessionBuilder::max_connections` explicitly.
- **Legacy feature names remain accepted** — `h2-native` is retained as a
  compatibility alias even though `lkh2` is now the only HTTP/2 engine, and
  `network-e2e` continues to gate public-network QUIC integration tests. This
  prevents existing Cargo invocations from failing during a patch upgrade.
- **WebSocket close codes and reasons are validated before they go on the
  wire** — `1005`, `1006` and `1015` may never be sent (RFC 6455 §7.4.1), and
  a reason longer than 123 bytes cannot fit a control frame.

### 修复（中文）

- **ECH 被拒绝后中止，而不是把外层连接交给应用** — 服务端未接受 Encrypted
  ClientHello 时，`lktls` 只打一行日志就继续：安装应用流量密钥，把一条真实服务器
  名从未被保护过的连接交给调用方，于是 ECH 本要隐藏的那个请求明文发了出去。
  RFC 9849 §6.1.6 规定外层握手只能用于认证 config 的 `public_name` 和取回
  `retry_configs`。现在 TCP 与 QUIC 两条路径都在那里中止 —— 早于任何流量密钥和
  session-ticket 上下文的产生 —— TCP 还会在 client Finished 之后发出
  `ech_required` alert（121，新建模）。拒绝路径上的证书验证改为针对
  `public_name`（服务端实际出示的身份），而不是拿一个它从未声称的名字去验证。
  GREASE ECH 不受影响：它不是 ECH offer，服务端忽略它并没有拒绝任何东西。
- **ECH 被拒绝后用服务端给的 `retry_configs` 重试一次** — ECH 会由 DNS HTTPS
  记录自动启用，所以只中止不重试会把一次例行的 ECH 密钥轮换变成普通流量的硬失败。
  现在 Session 会用服务端提供的 config 重拨一次，与浏览器做法一致。**不**回退到
  「不带 ECH 重试」：那会泄漏 ECH 正要保护的那个名字。
- **TLS 后握手消息分帧** — 后握手消息与握手本身遵循同样的分帧规则（RFC 8446
  §5.1）：多条可以合并进一个 record，一条也可以跨多个 record。此前每个 record 被
  当作恰好一条消息，因此与 `NewSessionTicket` 合并在同一 record 的 `KeyUpdate`
  会被静默丢弃 —— 读密钥永不轮换，之后所有 record 解密失败；合并发送的第二张
  ticket 同样丢失。现在解密后的握手字节先进缓冲，只有完整消息才被分发，与握手期
  的重组逻辑一致。
- **HTTP/2 `NO_ERROR` GOAWAY** — 优雅关闭（Google、Cloudflare 常规的连接轮换）
  携带 `NO_ERROR`，因此不置连接错误，而 draining 判断却读取「是否有错误」。
  driver 会继续在对端已承诺拒绝的连接上开新流（RFC 9113 §6.8）。现在 draining
  直接以「是否收到 GOAWAY」为准，排队请求会转到新连接；同时暴露 GOAWAY 的
  `last_stream_id`，供调用方区分已处理与未处理的流。
- **`304 Not Modified` 不再被当作重定向** — 此前所有 3xx 都被归类为重定向，条件
  请求得到的 `304`（以及 `300`/`305`/`306`）会走到 `Location` 提取并以
  `redirect response missing Location header` 失败。现在只跟随
  `301`/`302`/`303`/`307`/`308`，其余原样返回调用方（RFC 9110 §15.4）。
- **`Content-Encoding: deflate` 支持 zlib 形式** — RFC 9110 §8.4.1.2 定义的
  `deflate` 是 zlib 格式（RFC 1950），但此前只能解裸 RFC 1951 流，符合规范的服务
  端一律失败。一次性与流式路径现在都会嗅探 zlib 头并选择对应解码器；流式路径会先
  暂存开头字节，直到能判定格式为止。
- **备用服务不再提供 TLS 身份** — Alt-Svc 条目或 HTTPS RR 说的是「往哪里发包」，
  但该端点仍须证明自己有权服务该 origin（RFC 7838 §3.1、RFC 9460 §2.3）。此前广告
  出来的主机被同时用作 SNI 与证书校验名，于是备用端点是以「它自己」的身份通过认证
  的；而且符合规范的部署会直接失败——HTTPS RR 的 `TargetName` 通常是 CDN 的内部
  名，用的却是 origin 的证书。拨号目标仍然跟随广告。
- **状态码重试也要过幂等闸门** — 错误重试路径检查 `retry_is_replay_safe`，状态码
  路径却什么都不查，于是一个收到 `502` 的 `POST` 会被发第二次。既然服务端已经作
  答，请求必然已被处理。
- **WebSocket 握手响应会被校验** — 此前只看 `101` 状态码，`Upgrade`、`Connection`、
  `Sec-WebSocket-Accept` 以及服务端回选的扩展与子协议一概不验。现在五项全部失败即
  拒绝（RFC 6455 §4.1）：服务端若回选一个我们从未提供的扩展或子协议，连接不再建立。
- **`multipart/form-data` 不再自报家门** — boundary 此前构造成
  `----lkrequest{hex}`，等于每个上传请求的 `Content-Type` 里都写着库名，服务端一条
  正则就能识别，TLS 与 HTTP/2 指纹做得再像也无济于事。现在与真实 Chrome 151 一致，
  且是**实测所得而非推测**（`tests/b_layer_chrome_multipart.rs` 驱动真实浏览器打本地
  明文服务器）：`----WebKitFormBoundary` 加恰好 16 位字母数字。随机部分用拒绝采样，
  以保证字符分布均匀——`byte % 62` 会让前 8 个字母偏多，而分布倾斜本身就是破绽。
  **本条改变线上字节。**
- **multipart 字段名与文件名按 Chrome 的规则转义** — 此前原样插入
  `Content-Disposition`，于是调用方给的名字里若含 CR 或 LF，就能终止该头行
  （RFC 5322 §2.2）并追加 part 头、开出额外的 part、甚至伪造 boundary。据同一份实测：
  `"` 编码为 `%22`，CR / LF 编码为 `%0D` / `%0A`，其余一切——反斜杠、`;`、非 ASCII
  ——原样作为 UTF-8 送出。有一处光读 RFC 绝对推不出来的不对称：**字段名**会先把换行
  归一化成 CRLF，所以单独的 CR 和单独的 LF 都变成 `%0D%0A`；而**文件名不归一化**，
  单独的 LF 就是 `%0A`。`Content-Type` 不是带引号的参数，套不上这套编码，因此其中的
  CR / LF 直接拒绝（Chrome 的做法是整个丢弃、改送 `application/octet-stream`；报错比
  静默替换好排查，而两者都不会把异常字节送上线）。
- **TLS 1.2 的 `HelloRequest` 以 fatal alert 拒绝，不再静默忽略** — 此前直接丢弃，
  而没有任何浏览器会这么做，等于给任何愿意发一个 `HelloRequest` 的服务端留了个行为
  探针。BoringSSL 客户端默认 `ssl_renegotiate_never`，该模式下发 **fatal** 的
  `no_renegotiation` 并中止；Chrome 握手后也会落到同一状态，除非协商出的 ALPN 在
  `renego_allowed_for_protos` 里——该表默认为空，且永远不可能含 h2（RFC 9113 §9.2.1
  直接禁止重协商）。注意这个 alert 是 fatal，尽管 RFC 5246 §7.2.2 把
  `no_renegotiation` 归为 warning——这处偏离是 BoringSSL 的，而我们要跟的是浏览器。
  **行为变更：**此类连接现在以 `ConnectionAborted` 结束，此前会照常继续。
- **服务端选了我们从未提供的算法时，握手会失败** — TLS 1.2 的 `named_curve`、
  `ServerKeyExchange` 的签名算法、TLS 1.3 `CertificateVerify` 的签名方案，此前都只
  对照「实现是否支持」，从不对照「ClientHello 是否广告过」。在未广告的算法上完成握
  手，是服务端可见的矛盾。重复扩展检测此前也只在 HelloRetryRequest 分支运行；
  `CertificateVerify` 现在按 RFC 8446 §4.4.3 拒绝 `rsa_pkcs1_*`。
- **发送时遵守对端的 `record_size_limit`（RFC 8449）** — 该扩展只广告不执行，记录恒
  按 16384 字节切分，于是要求更小记录的对端仍会收到超限记录。
- **TLS 记录层收紧，会话票据的信任被限时** — 装了握手密钥之后仍接受明文的
  handshake 与 alert 记录；未知的记录 `content_type` 被静默跳过，而 RFC 8446 §5.1
  要求回 `unexpected_message`；TLS 1.2 恢复既不记录也不校验 Extended Master Secret
  状态（RFC 7627）；票据生命期无上限，现在封顶七天。后握手阶段读取器的装配也改用我
  方广告的 `record_size_limit`。
- **拒绝未经请求的 TLS 1.2 扩展，丢弃端口为 0 的备用服务** — TLS 1.2 解析器缺少
  「我们是否 offer 过」的检查，不像 TLS 1.3 那条路径。另外 `h3=":0"` 会产生一个指向
  RFC 6335 §6 保留端口的备用权威，那里不可能有监听者。
- **连接在没有 `close_notify` 的情况下结束，现在可与正常收尾区分** — 两者此前产生
  完全相同的 EOF，于是对靠连接关闭定界的响应体（RFC 9112 §6.3），截断与完整响应无
  法区分。`TlsStream::received_close_notify()` 现在报告实际发生的是哪一种，
  `ClientBuilder::require_close_notify(true)` 可把有歧义的那种变成 `UnexpectedEof`。
  **默认关闭**——大量生产服务端就是直接断连接，浏览器也接受。其中有一半是无条件的：
  读循环收到 `close_notify` 即停止，不再继续轮询，因为按 RFC 8446 §6.1，其后到达的
  任何字节都不可能来自对端，而那些字节此前会被追加进响应体。
- **HTTP/2 响应改为校验，而不是悄悄修补** — `content-length` 与实际收到的 DATA 不
  符会被接受（响应长度 desync）；解析失败的头被丢弃；缺失或非法的 `:status` 变成
  `500`。现在按 RFC 9113 §8.2.2 拒绝 connection-specific 字段（`Connection`、
  `Transfer-Encoding`、`Keep-Alive`、`Proxy-Connection`），强制伪头规则，DATA 与
  HEADERS 同等对待，且 `101` 不再被当作 interim 状态（HTTP/2 不使用它）。
- **畸形的 HTTP/2 响应现在会重置该流** — RFC 9113 §8.1.1 规定这是 PROTOCOL_ERROR
  类型的**流**错误，但此前什么都不往线上写。Chromium 的 netlog 事件链是
  `HTTP2_SESSION_RECV_INVALID_HEADER` → `HTTP2_SESSION_SEND_RST_STREAM`，所以沉默
  才是偏离、不是保真；而且沉默会让服务端继续在一条已被拆掉的流上发 DATA，该流的流
  控窗口永不归还。
- **HTTP/2 连接状态机对协议错误更严格** — 帧可以插进 CONTINUATION 序列中间；
  HEADERS 路径的流状态检查弱于 DATA 路径；所有 `SETTINGS` 错误一律映射成
  PROTOCOL_ERROR，而 `INITIAL_WINDOW_SIZE` 溢出必须是 FLOW_CONTROL_ERROR；本地连接
  错误后不进入终止态。修 DATA 路径时顺带堵上一个既有的连接级流控泄漏：到达一条无法
  接收的流上的帧会消耗连接窗口，却从不补回。
- **DNS HTTPS/SVCB 记录按「整条记录」读取，不再逐字段拼接** — 同优先级记录的字段被
  混在一起，拼出没有任何服务端发布过的端点描述；`AliasMode` 不被跟随；`mandatory`
  （key 0）与 `no-default-alpn`（key 2）被静默吞掉，于是可能用该端点明确声明不支持的
  协议去连接。别名链现在会跟随，并带环路检测与跳数上限。
- **备用服务保留 IPv6 的方括号形式，并解析 `persist`** — 解析时剥掉了方括号，而
  `Url::host_str()` 保留，于是裸的 `2001:db8::1` 会进到拨号器且无法使用。
- **HTTPS-RR 发现每请求只查一次，而非两次** — 协议发现与 TLS 握手的 ECH 自动配置各
  查各的。除了多一次往返，两次答案还可能不一致：ECH 密钥轮换或解析器做了负载均衡，
  都会让 ECH 配置与当初做出 H3 决策的那个端点对不上。
- **忽略 draft 版 HTTP/3 广告** — `select_h3` 会回退到任意 `h3-*`（含 `h3-29`），而
  Chrome 140+ 只认 `h3`。
- **校验 QUIC early-data 票据、HTTP/3 SETTINGS 与 HTTP/3 ECH** — QUIC 票据的
  `max_early_data_size` 只要非零就被接受，而 RFC 9001 §4.6.1 要求精确等于
  `0xffffffff`；自定义 H3 profile 可以发出保留的设置标识符；H3 路径还缺了 TCP 路径
  早已具备的三级 ECH 配置回退中的两级。
- **重定向只在规范要求的地方改写方法** — `301`、`302`、`303` 无条件变成 `GET`，于是
  一个 `HEAD` 请求会以 `GET` 返回，而 Chrome 不会这么做。`303` 仍然改写除 `HEAD` 以
  外的一切（RFC 9110 §15.4.4）。
- **解码多层 `Content-Encoding`** — 此前只处理最外层，于是 `gzip, br` 被原样返回，
  头里却声称已解码。现在按逆序逐层应用，一次性与流式路径都是如此。
- **强制 cookie 名前缀，忽略明文 HTTP 上收到的 `Secure` cookie** — `__Secure-` 与
  `__Host-` 只有在其要求被检查时才具有安全含义（RFC 6265bis §5.6）；而在明文 HTTP
  上收到的 `Secure` cookie，无论叫什么名字此前都会被存下。
- **HSTS 只从安全传输上学习，且绝不对 IP 字面量生效** — 一个明文 HTTP 响应可以往使
  用 `DynamicHsts` 的会话里注入 `Strict-Transport-Security` 策略（RFC 6797 §8.1）。
- **校验 SOCKS5 子协商回复，CONNECT 隧道接受任意 2xx** — 用户名/密码回复的版本字节
  从不校验（RFC 1929）；而 CONNECT 只接受精确的 `200`，RFC 9110 §9.3.6 规定任何 2xx
  都表示成功。
- **Session 默认不再限制为 64 条物理连接** — 隐式上限会让无关的高并发负载报
  `session connection limit reached`。默认值现为不设上限；需要硬预算的调用方仍可显式
  设置 `max_connections_per_session` 或 `SessionBuilder::max_connections`。
- **保留旧 feature 名称兼容性** — `h2-native` 继续作为兼容别名存在，尽管 `lkh2`
  已是唯一 HTTP/2 引擎；`network-e2e` 继续控制公网 QUIC 集成测试。补丁升级时，现有
  Cargo 命令不会因为 feature 消失而解析失败。
- **WebSocket 的 close code 与 reason 在上线前被校验** — `1005`、`1006`、`1015` 永远
  不得发送（RFC 6455 §7.4.1），且 reason 超过 123 字节放不进控制帧。

### Internal

- **The offline fingerprint gate covers every preset, not six of them** — it
  gated chrome_131/144/145/146/147/148, so chrome_149/150/151, firefox_133/147
  and safari_18/26 shipped with no byte-level regression gate. There was an
  inversion too: chrome_150_quic and chrome_151_quic had QUIC goldens while
  chrome_150 and chrome_151 had no TLS golden, leaving the newer builds better
  protected on QUIC than on the transport they actually use. 14 new goldens; the
  gate goes from 12 tests to 26. These lock in the bytes we emit today, so they
  catch drift from here on — they are not evidence that today matches the real
  browser, which is what the `#[ignore]`d Tier-2 tests are for.
- **Line endings are pinned to LF via `.gitattributes`** — committed blobs were
  a CRLF/LF mix, and `lkh2/src/adapter.rs` was mixed within one file, so rustfmt
  turned a three-line edit into a thousand-line diff. 162 files renormalised
  with no content change.

### 内部（中文）

- **离线指纹门覆盖全部 preset，而非其中六个** — 此前只守 chrome_131/144/145/146/
  147/148，于是 chrome_149/150/151、firefox_133/147、safari_18/26 全都没有字节级
  回归门。还有一处倒挂：chrome_150_quic 与 chrome_151_quic 有 QUIC 黄金文件，而
  chrome_150、chrome_151 没有 TLS 黄金文件，新版本在 QUIC 上反而比在它们实际主用的
  传输上守得更严。新增 14 个黄金文件，门从 12 个测试增至 26 个。它们锁的是**今天**
  发出的字节，能挡住此后的漂移；但不构成「今天等于真实浏览器」的证据——后者由标了
  `#[ignore]` 的 Tier-2 测试负责。
- **用 `.gitattributes` 把行尾固定为 LF** — 提交的 blob 此前 CRLF/LF 混杂，
  `lkh2/src/adapter.rs` 甚至单文件内部就混，于是 rustfmt 会把三行改动变成上千行
  diff。归一化 162 个文件，内容无变化。

## lkrequest 0.2.1

This patch release contains reliability, compatibility, and release-artifact fixes developed after **v0.2.0**.

### Fixes

- **Optional TLS client-certificate requests** — TLS 1.2 and TLS 1.3 now send an empty client `Certificate` when a server requests a client certificate but does not require one. TLS 1.3 echoes the request context and both protocol paths preserve the correct transcript. Explicit client-certificate authentication remains outside the public API.
- **HTTP/2 informational responses and connection accounting** — native H2 consumes `1xx` responses such as `103 Early Hints` until the final response arrives. Session connection limits now count physical H1/H2/H3 connections instead of multiplexed streams, including raced H2 drivers that may already own an active request.
- **HTTP/1.1 redirect reconnects** — canceled or closed pooled H1 connections encountered while following a redirect are classified as connection closures, evicted, and retried on a fresh connection.
- **Resolved-address fallback** — direct TCP and SOCKS5 connection setup retry resolved IPv4/IPv6 candidates in resolver order instead of failing after the first address.
- **System DNS request coalescing and optional positive cache** — the default `SystemDns` now coalesces concurrent lookups for the same `(host, port)` process-wide, shares successes and errors between waiters, and keeps the lookup alive if the initiating waiter is canceled. Completed lookups remain uncached by default. `SystemDnsCacheConfig` and `ClientBuilder::system_dns_cache` provide an opt-in instance-local positive cache with configurable TTL and capacity; errors and empty results are never cached.
- **HTTP/2 stream-limit backpressure** — requests wait for capacity when the peer's concurrent-stream limit is exhausted, preventing unnecessary H1 fallback and excess physical connections.
- **Legacy `ConnectionPool` API compatibility** — the low-level acquisition and mutation signatures published in 0.2.0 are restored as deprecated wrappers. Checked-out H1 permits remain accounted across pool clearing, and legacy H3 permits stay attached until their driver terminates instead of aborting active work during ordinary eviction. Internal Session paths continue using permit-aware methods while downstream users migrate before the wrappers are removed in 0.3.0.

### CI and Compatibility

- **Portable Linux FFI artifacts** — the FFI build image is pinned to Debian bookworm and CI verifies that published shared libraries require no GLIBC symbol newer than 2.36.

### 修复（中文）

- **TLS 可选客户端证书请求** — TLS 1.2 与 TLS 1.3 服务端请求但不强制要求客户端身份时，现在会发送空的客户端 `Certificate`。TLS 1.3 会回显 request context，两个协议路径都会维护正确的 transcript。显式客户端证书认证仍不属于当前公开 API。
- **HTTP/2 信息响应与连接计数** — 原生 H2 会持续消费 `103 Early Hints` 等 `1xx` 响应，直到最终响应到达。Session 连接上限现在按实际 H1/H2/H3 物理连接计数，而不是按复用 stream 计数；已经承载活动请求的竞态 H2 driver 也会被正确计入。
- **HTTP/1.1 重定向重连** — 跟随重定向时遇到被取消或关闭的池化 H1 连接，会将其识别为连接关闭、淘汰并通过新连接重试。
- **解析地址回退** — 直连 TCP 与 SOCKS5 建连会按 resolver 顺序重试多个 IPv4/IPv6 地址，而不是首个地址失败后立即终止。
- **系统 DNS 请求合并与可选正向缓存** — 默认 `SystemDns` 会在进程范围内合并相同 `(host, port)` 的并发查询，让等待者共享成功结果或错误；即使最初发起查询的等待者被取消，底层查询仍会继续。查询完成后默认不缓存。新增 `SystemDnsCacheConfig` 与 `ClientBuilder::system_dns_cache`，可按实例启用带 TTL 和容量限制的正向缓存；错误和空结果不会进入缓存。
- **HTTP/2 stream 上限背压** — 对端并发 stream 容量耗尽时，请求会等待可用容量，避免不必要的 H1 降级和额外物理连接。
- **旧版 `ConnectionPool` API 兼容** — 恢复 0.2.0 已发布的低层获取与写入签名，并标记为 deprecated。已取出的 H1 连接在清空池时仍会保留物理连接计数，旧版 H3 permit 也会持续绑定到 driver 结束，普通淘汰不会中断仍在运行的任务。Session 内部路径继续使用携带 permit 的方法，兼容入口计划在 0.3.0 移除。

### CI 与兼容性（中文）

- **Linux FFI 产物兼容性** — FFI 构建镜像固定为 Debian bookworm，CI 同时验证发布的动态库不会依赖高于 GLIBC 2.36 的符号版本。



## lkrequest 0.2.0

This release includes the changes developed since the initial **v0.1.0** release.

### 🚀 Features

- **Chrome 151 TLS / H2 / H3 preset** — Captured from Chrome 151.0.7922.72 on Windows on July 31, 2026. TCP TLS/H2 stable fields match Chrome 150. Public QUIC captures across Cloudflare, Google, Slack, and other H3 origins consistently remove the three ML-DSA signature algorithms while keeping the classic list plus `rsa_pkcs1_sha1`; QUIC transport and H3 SETTINGS remain aligned with Chrome 150's stable shape. Rust, FFI, synthesis, and profile-collector preset registries now expose `chrome_151`.

- **Dedicated Chrome 150 QUIC / HTTP/3 preset** — Chrome 150 now has its own QUIC-TLS and H3 profiles instead of reusing Chrome 146. The preset covers the captured signature-algorithm set, QUIC transport parameters, QPACK limits, navigation `PRIORITY_UPDATE`, connection-ID lengths, and Initial datagram sizing; milestone-, platform-, GREASE-, and Finch-dependent fields remain explicitly version-sensitive.
- **Fingerprint Randomization (`synthetic-fp`)** — Per-session *synthetic* fingerprints that stay browser-plausible: extension-order jitter, recombination from the shipped-preset corpus, and full out-of-corpus value perturbation — composable per layer (TLS / H2 / QUIC) through a `Layers` mask and materialized per session from a seed. A configurable **negotiability floor** keeps every synthetic ClientHello able to complete a real TLS handshake.
- **Multi-hop Proxy Chains** — Route through an ordered chain of proxies with `ProxyConfig::parse_chain([...])` / `.through(...)`. TCP (HTTP/1.1, HTTP/2) works with any mix of HTTP CONNECT and SOCKS5 hops. **QUIC/HTTP/3** additionally works over an **all-SOCKS5** chain via nested UDP ASSOCIATE (one UDP relay per hop, stacked as nested per-datagram headers); a chain containing an HTTP hop errors so the caller falls back to H2.
- **Pluggable HSTS Policy** — `HstsPolicy` trait to control `http`→`https` scheme upgrades (default off; `StaticHsts` / `DynamicHsts` provided).
- **FFI — Fingerprint Randomization** — `lk_client_builder_set_randomize` exposes the randomization tiers through the C ABI.
- **DNS — Fallible Hickory Constructors** — new fallible `HickoryDns` constructors with documented panic paths.

### 🐞 Fixes

- **TLS 1.3 ECH + HelloRetryRequest parity** — real ECH CH2 now reuses the ECH config, HPKE sender context, Inner random, GREASE values, and extension permutation; fake ECH bytes are also reused verbatim. HRR confirmation, selected-group, cookie-only retry, duplicate/invalid extension, dummy-CCS, and local fatal-alert handling now follow the browser/RFC flow.
- **ECH + PSK + HRR binders** — `pre_shared_key` remains exclusively in `ClientHelloInner`; CH1 uses `Truncate(ClientHelloInner1)` and CH2 uses `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)`. The previous unsupported-error path no longer aborts resumed real-ECH handshakes.
- **QUIC/H3 HRR state transitions** — QUIC immediately revokes 0-RTT stream and packet state after HRR, maps local TLS alerts to QUIC `CRYPTO_ERROR` codes, and completes a forced P-384 HRR through a real local H3 request/response flow.
- **TLS handshake reassembly across records** — a handshake message fragmented across several TLS records (RFC 8446 §5.1) — e.g. a large server Certificate flight, as Facebook sends — no longer fails the handshake with `truncated handshake message in record`. Both the TLS 1.3 and TLS 1.2 read paths now buffer decrypted handshake bytes and process only complete messages, matching what the QUIC path already did. Receive-side only: the ClientHello and all wire-visible client output (JA3/JA4/JA4_r, Akamai hash) are byte-for-byte unchanged.
- **Real ECH correctness & hardening** — corrected the Encrypted-ClientHello transcript, gated SVCB/ECH discovery lookups behind remote-DNS to close a DNS leak on `socks5h`/CONNECT routes, and restricted ALPS to HTTP/1.1 where applicable.
- **ALPS advertisement decoupled from payload** — advertising ALPS in the ClientHello no longer forces a non-empty client-settings payload, matching real Chrome (which advertises ALPS with an empty payload — a server-visible tell otherwise).
- **HTTP/2 `1xx` interim responses** — the native HTTP/2 driver now consumes `1xx` informational responses (e.g. `103 Early Hints`, which Cloudflare sends ahead of its `200`) and returns the subsequent final response, instead of surfacing the interim status as the final one. Fixes `GET https://www.cloudflare.com/` returning `103` instead of `200`.
- **HTTP/2 frame-size bound** — inbound frames are bounded by *our* advertised `MAX_FRAME_SIZE`, not the peer's.
- **Certificate DER bounds-checking** — a malicious certificate can no longer panic the TLS layer via out-of-range DER slices.
- **Redirect handling** — the total timeout now spans the entire redirect chain, `303 See Other` is followed correctly, and an opt-in `https_only` knob is available.
- **Middleware on retry** — `on_response` middleware now runs when a retry policy is configured.
- **SOCKS5 UDP reply matching** — relay replies are accepted on a source-**IP** match instead of exact `ip:port`. Real relays commonly egress replies from a UDP port other than the advertised `BND.PORT` (separate egress socket, relay pools, load balancers); the strict match dropped every such reply and hung QUIC-over-SOCKS5. quinn's header protection + AEAD still reject forged packets.

### 🔒 Security & Dependencies

- **crossbeam-epoch → 0.9.20** — RUSTSEC-2026-0204.
- **quinn-proto → 0.11.15** — backported fix for RUSTSEC-2026-0185.

---

### 🚀 功能（中文）

- **Chrome 151 TLS / H2 / H3 预设** — 已于 2026 年 7 月 31 日从 Windows Chrome 151.0.7922.72 实际抓取。TCP TLS/H2 稳定字段与 Chrome 150 一致；Cloudflare、Google、Slack 等多个公网 H3 站点的 QUIC 抓包一致移除了三个 ML-DSA 签名算法，保留经典列表并追加 `rsa_pkcs1_sha1`，QUIC Transport Parameters 与 H3 SETTINGS 的稳定形状延续 Chrome 150。Rust、FFI、合成语料和 profile-collector 均已注册 `chrome_151`。

- **独立 Chrome 150 QUIC / HTTP/3 预设** — Chrome 150 不再复用 Chrome 146 的 QUIC-TLS 与 H3 profile；新预设覆盖抓包确认的签名算法、QUIC Transport Parameters、QPACK 上限、导航请求 `PRIORITY_UPDATE`、Connection ID 长度和 Initial datagram 尺寸。与 milestone、平台、GREASE 和 Finch 相关的字段继续明确标记为版本易变项。
- **指纹随机化（`synthetic-fp`）** — 每个会话生成保持“像浏览器”的*合成*指纹：扩展顺序抖动、从已内置预设语料库重组、以及完全的语料外取值扰动 —— 可通过 `Layers` 掩码按层（TLS / H2 / QUIC）组合，并由种子在每个会话中具体化。可配置的**可协商底线**保证每个合成 ClientHello 都能完成真实 TLS 握手。
- **多跳代理链** — 用 `ProxyConfig::parse_chain([...])` / `.through(...)` 经一串有序代理转发。TCP（HTTP/1.1、HTTP/2）支持 HTTP CONNECT 与 SOCKS5 任意混合的跳。**QUIC/HTTP/3** 额外支持在**全 SOCKS5** 链上运行，采用嵌套 UDP ASSOCIATE（每跳一个 UDP relay，逐跳堆叠嵌套头）；链中若含 HTTP 跳则报错，由调用方回退 H2。
- **可插拔 HSTS 策略** — `HstsPolicy` trait 控制 `http`→`https` 协议升级（默认关闭；提供 `StaticHsts` / `DynamicHsts`）。
- **FFI —— 指纹随机化** — `lk_client_builder_set_randomize` 通过 C ABI 暴露随机化档位。
- **DNS —— 可失败的 Hickory 构造器** — 新增可返回错误的 `HickoryDns` 构造器，并文档化了 panic 路径。

### 🐞 修复（中文）

- **TLS 1.3 ECH + HelloRetryRequest 对齐** — real ECH CH2 现在复用 ECH config、HPKE sender context、Inner random、GREASE values 和扩展排列；fake ECH bytes 也逐字节复用。HRR confirmation、selected-group、cookie-only retry、重复/非法扩展、dummy CCS 与本地 fatal alert 均按浏览器/RFC 流程处理。
- **ECH + PSK + HRR binder** — `pre_shared_key` 仅存在于 `ClientHelloInner`；CH1 使用 `Truncate(ClientHelloInner1)`，CH2 使用 `message_hash(ClientHelloInner1) + HRR + Truncate(ClientHelloInner2)`。此前明确报不支持并中止的 real-ECH 恢复握手路径已补齐。
- **QUIC/H3 HRR 状态切换** — 收到 HRR 后立即撤销 QUIC 0-RTT stream/packet 状态；本地 TLS alert 映射为 QUIC `CRYPTO_ERROR`；强制 P-384 HRR 已通过真实本地 H3 request/response 流程。
- **TLS 握手跨 record 重组** — 一条握手消息被拆分到多个 TLS record 时（RFC 8446 §5.1，例如 Facebook 那样较大的服务器 Certificate flight），不再以 `truncated handshake message in record` 握手失败。TLS 1.3 与 TLS 1.2 的读取路径现在都会缓冲解密后的握手字节、只处理完整消息（QUIC 路径早已如此）。**仅接收侧改动**:ClientHello 及所有线上可见的客户端输出(JA3/JA4/JA4_r、Akamai hash)逐字节不变。
- **真实 ECH 正确性与加固** — 修正加密 ClientHello 的转录（transcript）；把 SVCB/ECH 发现查询限制在远程 DNS 下，堵住 `socks5h`/CONNECT 路由上的 DNS 泄漏；在适用处将 ALPS 限定为 HTTP/1.1。
- **ALPS 宣告与载荷解耦** — 在 ClientHello 里宣告 ALPS 不再强制一个非空的 client-settings 载荷，与真实 Chrome 一致（Chrome 宣告 ALPS 但载荷为空 —— 否则是一个服务端可见的破绽）。
- **HTTP/2 `1xx` 中间响应** — 原生 HTTP/2 驱动现在会消费 `1xx` 信息性响应（如 `103 Early Hints`，Cloudflare 会在 `200` 之前发送）并返回随后的最终响应，而不再把中间状态当作最终响应上报。修复了 `GET https://www.cloudflare.com/` 返回 `103` 而非 `200` 的问题。
- **HTTP/2 帧大小上限** — 入站帧以*我方*宣告的 `MAX_FRAME_SIZE` 为界，而非对端的。
- **证书 DER 边界检查** — 恶意证书不再能通过越界的 DER 切片让 TLS 层 panic。
- **重定向处理** — 总超时现在覆盖整条重定向链，`303 See Other` 被正确跟随，并提供可选的 `https_only` 开关。
- **重试时的中间件** — 配置了重试策略时，`on_response` 中间件现在会运行。
- **SOCKS5 UDP 回包匹配** — relay 回包改为按源 **IP** 匹配而非精确 `ip:port`。真实 relay 常从不同于 `BND.PORT` 的 UDP 端口回包（独立 egress socket、relay 池、负载均衡）；严格匹配会丢掉所有此类回包，导致 QUIC-over-SOCKS5 挂死。quinn 的头保护 + AEAD 仍会拒绝伪造包。

### 🔒 安全与依赖（中文）

- **crossbeam-epoch → 0.9.20** —— RUSTSEC-2026-0204。
- **quinn-proto → 0.11.15** —— 回移 RUSTSEC-2026-0185 的修复。



## lkrequest 0.1.0

> [!NOTE]
>
> This is the first major version.

### 🚀 Features

- **TLS Fingerprint Control** — Byte-level ClientHello generation that matches real browsers (Chrome, Firefox, Safari)
- **HTTP/2 Fingerprint Control** — SETTINGS frame order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames, and per-request priority weights
- **HTTP/3 + QUIC** — Optional `quic-h3` feature for full HTTP/3 over QUIC with fingerprint-aware Transport Parameters, Alt-Svc auto-discovery, and H2→H3 seamless upgrade
- **Built-in Browser Presets** — Chrome 131/144/145/146/147/148/149/150/151, Firefox 133/147, Safari 18/26 (TLS + H2, plus QUIC when `quic-h3` is enabled)
- **Session Management** — Cookie jars, connection pooling, HTTP/2 multiplexing, and optional QUIC 0-RTT session resumption
- **Connection Prewarming** — `session.preconnect()` pre-establishes DNS + TCP + TLS + H2 (or, with `quic-h3`, QUIC + H3) connections
- **Custom DNS Resolver** — Pluggable DNS with DoH support, auto ECH config and H3 hints via HTTPS/SVCB records
- **Alt-Svc Discovery** — Automatic HTTP/2 → HTTP/3 protocol upgrade via Alt-Svc headers with broken-QUIC fallback
- **SessionPool** — High-concurrency pool with proxy rotation (round-robin / random)
- **Proxy Support** — SOCKS5 and HTTP CONNECT with authentication
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) and H2 Extended CONNECT (RFC 8441)
- **Middleware** — Interceptor chain for request/response modification
- **Retry Policies** — Exponential backoff, fixed interval, custom strategies; idempotency-aware (non-idempotent methods are not silently replayed after a possibly-already-sent failure unless marked `Idempotency::Idempotent`)
- **Redirect Control** — `RedirectPolicy::Follow(n)` or `RedirectPolicy::None` for manual handling
- **Auto-Decompression** — Brotli, gzip, deflate, zstd
- **Blocking API** — Synchronous wrapper for non-async contexts
- **Multipart/Form-Data** — File uploads with streaming support
- **TCP Fingerprint** — JA4T-style TCP SYN fingerprinting
