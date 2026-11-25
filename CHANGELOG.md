# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-25

### Added

- Native TLS 1.3 client over a plain TCP socket, with a ClientHello matching the
  Chrome 152 fingerprint (GREASE, ALPN, ALPS, 512-byte padding).
- Full server certificate verification: chain, hostname and `CertificateVerify`
  signature (ECDSA, RSA PKCS#1 and RSA-PSS).
- Support for all three TLS 1.3 cipher suites: AES-128-GCM, AES-256-GCM and
  ChaCha20-Poly1305.
- Native HTTP/2: Chrome's SETTINGS and WINDOW_UPDATE, HEADERS, CONTINUATION,
  DATA, PING and flow control.
- Full HPACK: static table, dynamic table and Huffman decoding.
- Automatic HTTP/1.1 fallback when the server does not negotiate `h2`.
- Transparent `gzip` and `deflate` decompression; `br` and `zstd` when the
  extension is available.
- Redirects with a configurable limit.
- Default headers of a Chrome `fetch` request, with `sec-fetch-site` computed
  automatically.
- Bundled autoloader for use without Composer.
- Dependency-free test suite: RFC 7541 vectors, certificate validation, HTTP,
  compression and fingerprint checks.
- Documentation: internal architecture and shared-hosting guide.
- Eight runnable examples and a web demo.

### Notes

- No ML-KEM (`X25519MLKEM768`) support: the JA3 is close to Chrome's but not
  identical.
- No TLS session resumption, no 0-RTT, no HTTP/3 and no OCSP.

[Unreleased]: https://github.com/YOUR_USER/native-http/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/YOUR_USER/native-http/releases/tag/v1.0.0
