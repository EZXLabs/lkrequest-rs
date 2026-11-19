# Local Hickory Patch

Source: crates.io `hickory-proto` 0.26.3, upstream commit
`bd37cafbdd86112a6da32878f8c9bab22e14377e` (`crates/proto`).
Original crate SHA-256:
`12b92608f679a6fa515dd1d15c1ff89443026e391200a2c840c7afcba482893d`.
Original MIT and Apache-2.0 licenses are retained.
Cargo cache markers and the crates' standalone lockfiles are omitted; the
repository root lockfile controls the shipped dependency graph.
The upstream `.rustfmt.toml` is included in each crate to preserve its 2024
formatting style when the enclosing workspace runs `cargo fmt --all`.

The adjacent crates share that upstream commit. Original crate SHA-256 values:

- `hickory-net` 0.26.3: `c480823ed7c2c5d0f09c41020cb6b7c28029ce60ec42dc942158dcf22f8e0a4d`
- `hickory-resolver` 0.26.3: `3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981`

## Question Count Allocation

The upstream fix for RUSTSEC-2026-0491 caps initial record allocation and
`Message::read_queries`, but `Message::read` still allocates directly from the
untrusted question count. A 12-byte packet declaring 65535 questions allocates
5,767,080 bytes before failing. Cap the initial question capacity at eight,
matching the upstream helper; valid messages continue to grow the vector as
their questions are decoded. DNS wire output is unchanged. Advanced callers
use `lkrequest::dns::hickory` for configuration types: the local dependency
has a different Cargo source identity from a separately imported registry crate.

Regression coverage lives in `lkrequest/tests/dns_security.rs`; the same test
fails on the unmodified 0.26.3 release and passes with this one-line patch.
The adjacent resolver and net 0.26.3 sources have explicit path dependencies,
so downstream Git/path consumers also receive this fix. The resolver also
locally allows the new `AtomicU32::fetch_update` deprecation, retaining its
upstream Rust 1.88 minimum while building under `-D warnings` on newer Rust.
Root-level Cargo patches would not propagate to those consumers. Restore the
registry dependency and remove all three directories when an upstream release
passes the regression. A crates.io publication must first use such a fixed
upstream release (or separately published patched crates): Cargo strips local
paths while packaging. No vulnerability ID is assigned to this
additional finding; the existing advisory is context, not an assertion of
new upstream coverage.
