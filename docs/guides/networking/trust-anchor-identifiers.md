# Trust Anchor Identifiers

Trust Anchor Identifiers (TAI) let a TLS 1.3 client describe acceptable CA
identifiers and receive the server's certificate-selection hints. `lkrequest`
implements the X.509 client mechanism from
[draft-ietf-tls-trust-anchor-ids-06](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-06.html)
using extension `0xca34` for TCP and, with `quic-h3`, QUIC.

TAI never changes certificate trust. Verification still uses `rustls-webpki`
with Mozilla roots and explicitly added custom/native roots. An advertised ID
does not install a CA. The ID is assigned metadata, not a hash derived from a
server certificate.

## Select A Policy

The default policy preserves the selected fingerprint's advertised bytes and
ordering, with recovery disabled. Chrome 155, 156 and 157 presets preserve
their sorted ID lists for both TCP and QUIC. Extension permutation remains
independent of ID ordering.

The checked builds (155.0.8059.40, 156.0.8078.48 and 157.0.8103.39) sort ID
byte vectors before encoding. With the same ID set and configuration, the
internal order stays the same across connections and process restarts.
Root-store metadata, browser updates, feature switches and MTC configuration
can change the advertised set; these changes are not random permutations.

Chrome 152.0.7977.65 instead iterates an unordered hash set. Its order can
differ across processes, but is not guaranteed to change on every restart;
it does not explicitly shuffle the IDs for every handshake. The older
Chrome 152-154 presets retain a per-handshake shuffle approximation and do
not establish exact browser ordering or its lifetime. A custom profile's
`TrustAnchorIds.shuffle` explicitly requests per-handshake randomization.

```rust
use lkrequest::{Client, TrustAnchorPolicy, TrustAnchorRecovery};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder()
    .preset(lkrequest::preset::chrome_157())
    .trust_anchor_policy(TrustAnchorPolicy {
        recovery: TrustAnchorRecovery::Once,
        ..Default::default()
    })
    .try_build()?;
# Ok(())
# }
```

`TrustAnchorAdvertisement::Trusted` replaces the profile's list with sorted,
deduplicated IDs bound to roots actually present in the effective store. Only
known bindings are advertised; roots without metadata are still trusted by
the verifier. Each configured TLS profile must have a TAI extension slot.
`try_build()` reports invalid settings; `build()` panics for them.

When recovery is enabled, an unknown issuer or an eligible peer close/alert
after a valid server TAI list can trigger a new connection. The client chooses
the first locally usable ID in server preference order, then requests that
single ID. The connection keeps the same target, proxy route, origin name,
and ECH configuration. Direct target addresses are pinned across attempts;
remote DNS remains the proxy's responsibility. Both attempts share the
connection deadline and physical connection budget.

There is at most one TAI recovery per request, shared by protocol alternatives
and redirects. Failed recovery is terminal for automatic HTTP retries. A
preconnect operation independently permits one recovery. No HTTP bytes are
sent on the rejected connection. Recovery policy suppresses 0-RTT even if a
ticket permits it; ordinary PSK resumption remains available on the first
attempt, and recovery performs a full handshake.

Wrong names, expired certificates, invalid signatures, malformed extensions,
and ECH rejection do not trigger TAI recovery. ECH rejection uses the existing
ECH flow. Recovery requires verification, usable metadata, and profiles that
can change their advertised IDs. Negotiation settings are incompatible with
strict ClientHello mirrors and TLS synthesis; extension-order randomization
is supported. Recovery also disallows proxy-to-direct fallback.
Optional recovery is draft behavior, not a claim that Chrome 157 makes the
same recovery connection.

## Bind A Custom Root

Load the root explicitly, then bind its assigned ID. Obtain the ID from the
CA or trusted configuration. Do not derive an ID from the identity hash.

```rust
use lkrequest::{Client, TrustAnchorBinding, TrustAnchorId};
use lkrequest::lktls::{trust_anchor::anchor_identity, verify::certchain::parse_trust_anchor_from_der};

# fn configure(root_der: &[u8]) -> Result<Client, Box<dyn std::error::Error>> {
let anchor = parse_trust_anchor_from_der(root_der)?;
let client = Client::builder()
    .add_ca_cert_der(root_der)
    .trust_anchor_binding(TrustAnchorBinding {
        anchor_identity: anchor_identity(&anchor),
        id: TrustAnchorId::from_hex("81fd5901")?, // example private deployment ID
    })
    .try_build()?;
# Ok(client)
# }
```

IDs contain 1..32 bytes of minimal DER RELATIVE-OID contents, without ASN.1
tag/length or TLS length prefixes. JSON represents these bytes as hexadecimal.
Bindings to absent roots and conflicting bindings for the same ID are
rejected. Anchor identity includes subject, public key and name constraints.
Client trust settings are immutable; new settings require a new client and
its sessions. Ticket caches are shared within an immutable client; a new
client gets a separate cache for its trust settings and TAI policy.

## Read Diagnostics

Enable `collect_diagnostics(true)` on the request and read
`response.diagnostics().and_then(|d| d.trust_anchor.as_ref())`. C response and
error diagnostics JSON includes the same `trust_anchor` object. It records
requested/available IDs, the certificate match indication, verified anchor
identity, authentication status, and both attempts after recovery. Peer hints
on a failed first attempt remain unauthenticated. Reused pooled connections
do not produce a new negotiation snapshot.

## C API

- `lk_client_builder_set_trust_anchor_policy_json`: accepts, for example,
  `{"advertisement":"profile","recovery":"once"}`.
- `lk_client_builder_add_trust_anchor_binding_json`: accepts
  `{"anchor_identity":"<64 lowercase hex characters>","id":"81fd5901"}`.
- `lk_trust_anchor_identity_from_der`: computes identity into a caller-owned
  buffer of at least 65 bytes, including the terminating NUL. It adds no trust.

Load custom roots with the existing CA configuration API before building.
Generated C headers contain the declarations; header files remain build artifacts.

## Scope

Bundled metadata is pinned to Chrome 157 root-store version 42. Its 28 IDs
describe 13 roots and 15 additional intermediates. Only effective roots are
eligible for trusted advertisement and recovery. Intermediate metadata does
not add roots or enable Chrome's intermediate-elision behavior.

MTC verification, group membership expansion, hot root-store updates, and
disabling path building for strict certification paths are not implemented.
TAI's certificate match indication is parsed while ordinary webpki path
building remains enabled.

## Validation

See [Testing Trust Anchor Identifiers](../../development/trust-anchor-testing.md)
for executable test commands, a coverage matrix, and remaining combination
limits. The Tier-1 BoringSSL peer independently exercises certificate selection,
the CertificateEntry match flag and a single recovery connection; it is
separate from the captured Chrome fingerprint regression.
