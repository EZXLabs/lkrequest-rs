# BoringSSL TAI Interoperability Peer

This Tier-1 peer uses BoringSSL's own TAI encoding, credential selection,
CertificateEntry match indication and TLS handshake. It listens on an ephemeral
IPv4 loopback port. The Rust test generates temporary keys and certificates,
starts the process, and removes those files after the process exits.

The first connection receives an untrusted fallback certificate. On the second,
the client requests only `81fd5901`; BoringSSL selects a leaf signed by the
locally trusted test root and sends the match indication. The assertions require
two connections, a verified root identity, and exactly one POST with its body.
This is an independent implementation check, not browser fingerprint evidence.

## Build

Use BoringSSL revision `5b83e5d1abf0ae0033ae52ab579d906b67633b2c`, the revision
pinned by the Chrome 157 investigation. Obtain the source in a separate local
directory; do not add it as a project dependency or commit the build output.
Building requires CMake and a C++17 compiler. The commands below disable
assembly so NASM is unnecessary for this peer.

```bash
git clone https://github.com/google/boringssl.git /tmp/tai-boringssl
git -C /tmp/tai-boringssl checkout 5b83e5d1abf0ae0033ae52ab579d906b67633b2c
cmake -S /tmp/tai-boringssl -B /tmp/tai-boringssl-build \
  -DOPENSSL_NO_ASM=ON -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/tai-boringssl-build --config Release --target ssl --parallel 2
cmake -S tools/tai_interop -B target/tai-peer \
  -DBORINGSSL_SOURCE_DIR=/tmp/tai-boringssl \
  -DBORINGSSL_BUILD_DIR=/tmp/tai-boringssl-build
cmake --build target/tai-peer --config Release --parallel 2
TAI_BORINGSSL_PEER="$PWD/target/tai-peer/tai_boringssl_peer" \
  cargo test -p lkrequest --test trust_anchor_negotiation boringssl -- --ignored
```

On Windows, run from a Visual Studio developer shell and use absolute paths:

```powershell
cmake -S C:/src/boringssl -B C:/build/boringssl -G "Visual Studio 17 2022" -A x64 -DOPENSSL_NO_ASM=ON -DBUILD_TESTING=OFF
cmake --build C:/build/boringssl --config Release --target ssl --parallel 2
cmake -S tools/tai_interop -B target/tai-peer -G "Visual Studio 17 2022" -A x64 -DBORINGSSL_SOURCE_DIR=C:/src/boringssl -DBORINGSSL_BUILD_DIR=C:/build/boringssl
cmake --build target/tai-peer --config Release --parallel 2
$env:TAI_BORINGSSL_PEER = "$PWD/target/tai-peer/Release/tai_boringssl_peer.exe"
cargo test -p lkrequest --test trust_anchor_negotiation boringssl -- --ignored
```

The Windows source directory must also be checked out at the revision above.
Only the Windows/MSVC path has been exercised locally; the POSIX build path
requires validation on a POSIX runner. The process has bounded accept/read waits
and is killed and reaped by the test on failure. No public-network service is
contacted while the test runs; downloading BoringSSL is a separate setup step.

See [the coverage matrix](../../docs/development/trust-anchor-testing.md) for
Tier-0 tests and the limits of this interoperability check.
