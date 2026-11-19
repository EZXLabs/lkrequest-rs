# Synthetic Handshake Signature Fixtures

Generated locally on 2026-11-10 with OpenSSL using new P-256 and P-384 keys.
Only public certificates and signatures are retained here; no private keys.
These self-signed certificates are used to verify handshake signatures, not
certificate trust or validity time.

The signed message is 64 bytes of 0x20, the ASCII string
`TLS 1.3, server CertificateVerify`, one zero byte, and 32 bytes of 0x42.
Each curve signs that same message with both SHA-256 and SHA-384.

OpenSSL operations: `req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256`
(or P-384), followed by `dgst -sha256 -sign` (or SHA-384). This provides an
independent signature source for TLS 1.2 hash-pair versus TLS 1.3 curve-binding
tests. Verification tests do not require an installed OpenSSL executable.
