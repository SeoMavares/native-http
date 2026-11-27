# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-26

### Added

- `examples/09-media.php`: saves a direct media URL to disk.
- Documentation for HPACK resources, test groups and request safeguards.

### Fixed

- Redirect `Location` values are resolved per RFC 3986 (`?query`, `../` and
  fragments).
- `Authorization`, `Cookie` and `Proxy-Authorization` are dropped when a
  redirect changes origin.
- Chunked HTTP/1.1 bodies, trailers and informational `1xx` responses are
  validated instead of being truncated silently.
- HTTP/2 frames are filtered by stream, `CONTINUATION` is enforced, padding is
  checked, and `SETTINGS` must be a valid connection frame.
- A `Host` header supplied by the caller no longer duplicates the authority.

### Changed

- Client options, HTTP methods and URLs are validated strictly; unknown options
  throw `InvalidArgumentException`.

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

[Unreleased]: https://github.com/SeoMavares/native-http/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/SeoMavares/native-http/releases/tag/v1.1.0
[1.0.0]: https://github.com/SeoMavares/native-http/releases/tag/v1.0.0
