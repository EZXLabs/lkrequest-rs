# Testing Trust Anchor Identifiers

The [TAI guide](../guides/networking/trust-anchor-identifiers.md) describes the
public contract. The tests below validate X.509 client negotiation and recovery
using `draft-ietf-tls-trust-anchor-ids-06` and extension `0xca34`.

## Run The Tests

Tier-0 uses loopback or in-memory peers and does not need public-network access:

```bash
cargo test -p lktls trust_anchor
cargo test -p lktls tai_
cargo test -p lkrequest --lib trust_anchor
cargo test -p lkrequest --test trust_anchor_negotiation
cargo test -p lkrequest --all-features --test trust_anchor_negotiation
cargo test -p lkrequest-ffi --test streaming_diagnostics_and_configuration trust_anchor
cargo test -p lkrequest-ffi --test streaming_diagnostics_and_configuration tai_ffi
```

The all-feature invocation includes QUIC/H3 and TLS-synthesis configuration
guards. The independent BoringSSL test is ignored by default and must be run
separately after building the [Tier-1 peer](../../tools/tai_interop/README.md).
Avoid a workspace-wide `--include-ignored`: unrelated targets include public
network tests.

For regression and C ABI validation:

```bash
cargo test --workspace -j 2
cargo test -p lkrequest --all-features --test quic_local_e2e --test fingerprint_regression -j 2
cargo test -p lkrequest-ffi -j 2
cargo clippy -p lkrequest --all-features --lib --test trust_anchor_negotiation -- -D warnings
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Coverage Matrix

| Contract | Evidence |
| --- | --- |
| Minimal RELATIVE-OID, large components, list framing and size limits | `lktls::trust_anchor::tests::wire_limits_oid_validation_and_order` |
| Metadata cannot add trust; conflicting bindings rejected; name constraints included in identity | `metadata_does_not_grant_trust` |
| Server preference order, unknown IDs and intermediate exclusion | `only_bound_roots_are_usable_in_server_preference_order` |
| EE cannot be empty or duplicated; certificate flag is empty, first-entry-only and nonduplicated | `tls13::tests::tai_*` and `validation::tai_empty_and_duplicate_server_extensions_are_terminal` |
| Chrome 155-157 TCP/QUIC IDs retain exact sorted payloads while extension permutations vary | `fingerprint_regression::chrome_155_to_157_trust_anchor_wire_order_matches_chromium` |
| Custom ID shuffling changes fresh handshakes but HRR reuses the first encoding | `custom_shuffled_trust_anchor_orders_vary_but_retry_uses_the_first_encoding` |
| Default fingerprint preserved; trusted advertisement sorted; incompatible configurations rejected | `tai_policies_validate_profiles_and_keep_default_fingerprint`, synthesis and FFI configuration tests |
| Unknown issuer recovers once; HTTP body is sent after verification | `tai_recovers_unknown_issuer_once_before_post`, `quic::tai_quic_recovers_with_singleton_request` |
| Default policy, absent server extension and no usable overlap do not recover | `tai_recovery_is_opt_in`, `validation::tai_no_*` |
| Wrong hostname, expiry and bad CertificateVerify are terminal | `tai_wrong_hostname_is_terminal`, `validation::tai_expired_certificate_is_terminal_on_the_wire`, `validation::tai_bad_certificate_verify_is_terminal_on_the_wire` |
| Encrypted peer alerts retain typed eligibility | `validation::tai_peer_alert_classification_uses_real_encrypted_records` |
| Brotli-compressed Certificate preserves TAI flag and rejects a malformed flag | `validation::tai_*compressed*` |
| ECH rejection does not use outer-handshake TAI hints | `validation::tai_ech_rejection_does_not_use_outer_hints` |
| HTTP CONNECT and SOCKS5h preserve authority, SNI and remote DNS with one physical connection slot | `lifecycle::tai_http_connect_*`, `lifecycle::tai_socks5h_*` |
| Recovery spends the remaining connection deadline | `lifecycle::tai_recovery_uses_remaining_connection_deadline` |
| Concurrent origins keep hints separate; cancellation releases the slot and next-request budget | `lifecycle::tai_concurrent_*`, `lifecycle::tai_cancelled_*`, request-budget unit tests |
| Redirects share a recovery budget; preconnect can recover and warm a reusable connection | `lifecycle::tai_recovery_budget_survives_redirect_to_another_origin`, `lifecycle::tai_preconnect_*` |
| Recovery singleton remains unchanged through a real HRR | `lifecycle::tai_singleton_request_is_stable_across_recovery_hello_retry_request` |
| TCP and QUIC preserve real PSK resumption; QUIC suppresses actual early-data offer when recovery is enabled | `lifecycle::tai_policy_preserves_real_tcp_psk_resumption_without_early_data`, `quic::tai_quic_policy_*`, `quic::tai_quic_default_policy_*` |
| Second failure retains both causes and automatic HTTP retries cannot open a third TAI connection | `tai_failed_recovery_retains_both_attempts_and_stops` |
| FFI response/error JSON retains requested IDs, authentication and both attempts | `trust_anchor_diagnostics::tai_ffi_recovery_*` |
| Independent server selects the requested credential and reports the actual trusted root | `boringssl::tai_boringssl_selects_trusted_credential_after_one_recovery` (Tier-1) |

Tests are in [the integration target](../../lkrequest/tests/trust_anchor_negotiation.rs)
and its `validation`, `lifecycle`, `quic`, and `boringssl` modules. FFI transport
tests are in [trust_anchor_diagnostics.rs](../../lkrequest-ffi/tests/support/trust_anchor_diagnostics.rs).
The shared controlled-flight helper is test-only. It stops before Finished;
successful handshakes use rustls or BoringSSL independently.

## Evidence Limits

The BoringSSL peer validates TCP certificate selection and recovery with a
test CA and leaf, including the match flag and actual verified-root identity.
It does not prove identical Chrome policy, Chrome Root Store equivalence, or
browser wire fidelity. Fingerprint evidence remains the captured preset and
the raw-payload regression in `fingerprint_regression`. Canonical TAI fixtures
compare membership after sorting; only the raw-payload assertion checks ID
ordering. It covers the checked Chrome 155-157 builds and does not establish
exact ordering behavior for older presets.

The suite is not an exhaustive cross-product. Accepted real ECH combined with
TAI recovery, QUIC recovery over SOCKS5 UDP/MASQUE, and sustained randomized
connection races still need dedicated interoperability or stress runs. ECH
rejection and Brotli Certificate processing are covered with controlled TCP
flights; ordinary QUIC/proxy regressions do not prove these combinations.
POSIX execution of the C++ peer also requires a corresponding runner check.

MTC, group membership expansion, hot trust-store updates, intermediate elision
and strict pre-built path validation are outside the implementation's scope.
They are not treated as covered by these tests.
