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

`connection::ClientConnection` owns a TCP connection from ClientHello through
authenticated application data, including record protection, bounded input and
output, alerts, KeyUpdate and tickets. An adapter feeds bytes with
`feed_bounded()`, drains `output()` by the actual transport write count and
acknowledges requested flushes. `TcpConnection` remains available for callers
that already completed a handshake with the legacy driver.
`connection::QuicClientConnection` owns QUIC handshake and ticket framing. Its
ordered output stops at each encryption-level transition; packet protection and
QUIC key updates remain with the transport. Neither endpoint performs socket I/O.

TLS 1.2 supports ECDHE RSA/ECDSA with AES-GCM, ChaCha20-Poly1305 and AES-CBC,
plus static-RSA AES suites and the three 3DES-CBC suites advertised by Safari.
CBC supports SHA-1/SHA-256/SHA-384 MACs
according to its suite and uses Encrypt-then-MAC when both peers negotiate it.
This applies to full and resumed handshakes. CBC and static RSA require the
historical security policy at explicitly compiled entry points.

CBC MAC-then-encrypt does not currently provide a constant-time record-opening
guarantee. Use the modern policy for forward-secret AEAD suites. EtM negotiation
authenticates the ciphertext before CBC decryption; it does not establish that
the separate MAC-then-encrypt implementation is timing resistant.

The low-level `Tls12TrafficKeys::to_record_cipher()` and installation helpers
retain MAC-then-encrypt defaults. Custom low-level drivers negotiating EtM must
use `to_record_cipher_with_mode()` with `Tls12Handshake::cbc_mac_mode()`.
`HandshakeDriver` performs this selection automatically.

TLS 1.2 strict handshake verification supports RSA/SHA-1 and ECDSA/SHA-1
with P-256 or P-521 keys. P-384 with ECDSA/SHA-1 is unsupported by the current
aws-lc-rs verification API and fails strict verification. P-384 with SHA-256
or SHA-384 is supported. This limitation does not relax certificate-chain
verification or permit SHA-1 handshake signatures in TLS 1.3.

P-521 (`secp521r1`, group `0x0019`) supports TLS 1.2 ECDHE and TLS 1.3
key shares, including HelloRetryRequest. TLS 1.2 accepts P-521 ECDSA signatures
with SHA-256, SHA-384 or SHA-512; TLS 1.3 binds scheme `0x0603` to P-521/SHA-512.
Certificate-chain verification also accepts P-521 signatures with these three
hashes. This completes the P-521 capabilities already advertised by applicable
Firefox/Safari profiles without changing their captured offers.

## Fingerprint profiles

Built-in profiles are loaded from `profiles/*.json` and exposed through `lktls::profile::presets`.
The latest family profiles are `chrome_158()`, `firefox_156()` and `safari_26()`
(Safari 26.2). Chrome also supplies transport-specific QUIC ClientHello profiles,
including `chrome_158_quic()`; Firefox and Safari do not have QUIC presets.
The high-level client's default remains Chrome 155. Use the support matrix for
capture versions and per-layer evidence rather than inferring fidelity from a name.

Profiles have different evidence levels, including captured, inherited, and
unverified fields; see the [support matrix](../docs/reference/presets.md).
Do not edit golden profiles merely to make a test pass; recapture the target
browser when its wire behavior changes.

## Shared configuration

`config::CompiledClientConfig` validates and shares immutable TLS inputs.
`HandshakeDriver::from_compiled()` and `QuicHandshakeDriver::from_compiled()`
accept the shared configuration plus `ConnectionInputs` for each attempt.
Hostname, ECH configuration, callbacks and the session store belong to the
attempt. Randomness, ephemeral keys and selected tickets are never cached in
the compiled configuration.

`ConnectionInputs::hello_overrides` provides validated generated ALPN, ALPS and
trust-anchor-ID overrides without modifying the shared profile. The same
effective offer is used for ClientHello, HRR/ECH and session selection. Raw
extension conflicts are rejected before cache take.
Legacy profile setters retain their existing profile-inspection semantics.

The default `CompileOptions` require implemented advertised capabilities and a
modern policy (TLS 1.2/1.3, forward secrecy, AEAD). Browser profiles may advertise
historical or unimplemented capabilities. `CompileOptions::compatibility()`
preserves those declarations and exposes `capability_issues()`; it does not
remove entries or promise interoperability for unsupported peer selections.
Admission and security policy can also be selected independently.
`ConnectionInputs::required_alpn` checks a transport's explicit protocol
requirement against raw ALPN/ALPS payloads before session selection. The high-level
H1-only and H3 paths supply that constraint; compatibility-mode profiles without
it retain their existing ALPS/resumption behavior.

`ClientConfigTemplate` supports deferred compilation for infallible builders.
Clones share one compilation result. Changes to the profile, verification policy
or trust anchors invalidate that result. The existing TCP and QUIC adapters use
these templates; `lkrequest::Client` retains separate bounded templates for
ordinary TCP, H1-only TCP and QUIC. Existing builder admission remains compatible.

## Session stores

`InMemorySessionStore` supports both TLS versions and preserves the verification
context of a completed handshake. A session is eligible only for the same
hostname, port, TCP/QUIC transport, verification policy and trust-anchor contents.
Changing that context causes a full handshake. TLS 1.2 additionally requires the
original suite and EMS state; TLS 1.3 applies its PSK hash and early-data rules.
TLS 1.2 tickets and session IDs are published after server Finished verification
succeeds. By default TLS 1.2 sessions may be reused for one hour from their
original handshake; a zero ticket lifetime is unspecified and uses this local
cap. Shorter server lifetimes take precedence. Ticket renewal does not extend
the age of the original secrets. Ticket attempts generate fresh session IDs;
only ID-only resumption sends a cached ID. Fatal TLS failures revoke the
associated session and all its retained copies. TLS 1.3 tickets remain
single-use with a seven-day cap, with zero
lifetime meaning immediate discard.

Use `InMemorySessionStore::new().with_ttl(Duration::from_secs(7200))` to
override the local TTL, or implement `SessionStore::session_cache_ttl()` in a
custom store. Zero prevents caching. Shorter server lifetimes and the TLS 1.3
seven-day protocol cap still apply. The chosen TLS 1.2 TTL is measured from the
original handshake and cannot be extended by renewal or moving to another
store. In `lkrequest`, use `.tls_session_cache_ttl(...)` and
`.tls_session_cache_enabled(false)` on the client builder.

Custom stores implement `SessionStore` and `ClientSessionStore`, returning
`Some(self)` from `SessionStore::client_sessions()`. Store and remove opaque
`ClientSession` values by ownership. Each TLS 1.3 take consumes its ticket once;
`ClientSession::clone_tls12()` lets stores retain reusable TLS 1.2 sessions
without changing their verification context or expiry.
Clones also share revocation state: `is_expired()` becomes true after a fatal
TLS failure, even in a custom store. A newer independent session is unaffected.
The built-in store, network-partition wrapper and early-data suppression wrapper
already implement this contract. `ClientSession::disable_early_data()` preserves
ordinary resumption while disabling 0-RTT.

Legacy `SessionStore` implementations still compile and receive ticket
notifications, but their bare `SessionTicketData` cannot authorize resumption.
Directly inserting a legacy ticket, or taking an opaque session through the
legacy API and reinserting the resulting fields, results in a cache miss on the
next handshake. Use `take_session()` and `store_session()` when moving sessions
between stores. There is currently no public persistence decoder for the opaque
type. Applications requiring persisted caches must use full handshakes until a
versioned persistence API is available.

These checks run during handshake setup and ticket publication; they add no
session-store lookup to the application-record path. Built-in root identity is
hashed once, while custom anchor contents are hashed during configuration
compilation and reused by drivers sharing that configuration.

## Validation

```bash
cargo test -p lktls
cargo bench -p lktls
cargo doc -p lktls --no-deps
```

The optional local OpenSSL matrix covers all implemented TLS 1.2 suites,
CBC with and without EtM, cross-curve ECDSA signatures, and TLS 1.3 AEAD suites,
with full and resumed handshakes. It is ignored by default and uses loopback:

```bash
TEST_OPENSSL=/path/to/openssl cargo test -p lktls --test tls12_openssl -- --ignored --nocapture
```

## License

Licensed under the Apache License 2.0.
