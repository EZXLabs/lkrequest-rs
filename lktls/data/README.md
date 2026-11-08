# Trust Anchor ID Metadata

`trust_anchor_ids.json` records the X.509 ID allocation from Chromium
`157.0.8103.39`, Chrome Root Store version 42:

- [root_store.textproto](https://raw.githubusercontent.com/chromium/chromium/157.0.8103.39/net/data/ssl/chrome_root_store/root_store.textproto)
- [root_store.certs](https://raw.githubusercontent.com/chromium/chromium/157.0.8103.39/net/data/ssl/chrome_root_store/root_store.certs)

Source SHA-256 digests are included in the generated JSON. Each entry retains
its assigned ID, certificate SHA-256, and original top-level metadata kind.
There are 13 `trust_anchors` and 15 `additional_certs` entries with IDs.
Additional intermediates deliberately have no usable anchor identity.

Root `anchor_identity` values use the same parser and identity function as
runtime verification. Regenerate them from reviewed allocation metadata and
the pinned certificate bundle:

```bash
cargo run -p lktls --example generate_trust_anchor_catalog -- \
  lktls/data/trust_anchor_ids.json root_store.certs /tmp/trust_anchor_ids.json
```

The example accepts either a JSON array of allocation entries or the generated
catalog as input. Changing the source revision requires reviewing the source
ID-to-certificate mapping and updating the example's pinned provenance. Verify
the source digests, review the diff and check all allocated IDs against the
browser capture before replacing this file. New source metadata must not
implicitly install certificates or assign identities to intermediates.

At runtime, metadata is intersected with the actual Mozilla/custom anchors by
subject, SPKI and name constraints. These data do not implement Chrome Root
Store's other policies, certificate retrieval, group expansion or MTC.
