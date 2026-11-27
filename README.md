# NativeHttp

[![PHP](https://img.shields.io/badge/php-%3E%3D8.1-777bb3.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)

A pure-PHP HTTP client with **its own TLS 1.3 and HTTP/2 stack**. No `ext-curl`,
no `curl` binary, no OpenSSL handshake. It greets servers with the TLS
fingerprint of a modern browser (Chrome 152).

Why? Because many sites reject clients that do not look like a browser. They do
not only check headers: they inspect the TLS handshake. With `curl` or
`file_get_contents()` you get a **403**; with this library you get a **200**.

```php
require 'vendor/autoload.php';

$client = new NativeHttp\Client();

$response = $client->get('https://example.com/api/data', ['Accept: application/json']);

echo $response['status'];   // 200
echo $response['body'];     // raw content
```

---

## Contents

- [Features](#features)
- [What can I use it for?](#what-can-i-use-it-for)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API](#api)
- [Examples](#examples)
- [How it works](#how-it-works)
- [Documentation](#documentation)
- [Resources](#resources)
- [Testing](#testing)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [License](#license)

---

## Features

| | |
|---|---|
| **Native TLS 1.3** | The ClientHello is built byte by byte: cipher order, curves, GREASE values and extension order as in Chrome 152. |
| **Native HTTP/2** | Frames, stream handling, SETTINGS and WINDOW_UPDATE with Chrome's values. |
| **Full HPACK** | Static table, dynamic table and Huffman decoding. |
| **HTTP/1.1 fallback** | If the server does not negotiate `h2`, HTTP/1.1 is used automatically. |
| **Certificate verification** | Chain, hostname and `CertificateVerify` signature (ECDSA and RSA-PSS). |
| **Compression** | `gzip` and `deflate` out of the box; `br`/`zstd` when the extension is installed. |
| **Redirects** | Up to 5 by default, configurable. |
| **Zero dependencies** | Works with a single `require`. Composer is optional. |
| **Shared-hosting friendly** | No SSH, no compiled extensions, no extra ports. |
| **PHP 8.1+** | Verified on 8.3 and 8.4; only needs `openssl` and `zlib`. |

## What can I use it for?

NativeHttp is useful for browser-like HTTPS requests from PHP, including
workflows where a site expects browser-style TLS and HTTP/2 behavior. Common
use cases include:

- Calling JSON APIs and retrieving HTML pages.
- Automating requests from cron jobs or shared hosting where installing
  `curl` or extra PHP extensions is inconvenient.
- Extracting links from pages and requesting the resources they point to,
  including direct media URLs such as MP4 files.
- Debugging TLS and HTTP/2 behavior with the included logger and fingerprint
  example.

NativeHttp returns the response body sent by the server. JavaScript included in
that HTML is returned as source; NativeHttp does not evaluate it in a browser
engine. If the server has already generated content before sending the
response, that generated content is available in the returned body.

## Requirements

| Requirement | Details |
|---|---|
| PHP | 8.1 or newer |
| `ext-openssl` | Required (bundled with almost every PHP build) |
| `ext-zlib` | Required (gzip / deflate) |
| `ext-gmp` or `ext-bcmath` | Recommended: verifies RSA-PSS signatures. If both are missing, sites using RSA-PSS certificates fail with a clear error. |
| `ext-brotli` / `ext-zstd` | Optional, only for responses compressed with those codecs |

Check your server:

```bash
php -v
php -m | grep -E 'openssl|zlib|gmp|bcmath'
```

## Installation

### Composer (recommended)

```bash
composer require nativehttp/client
```

```php
require 'vendor/autoload.php';

use NativeHttp\Client;
```

> The package follows PSR-4 (`NativeHttp\` → `src/`) and is ready for
> Packagist. Until it is published there, point Composer at the repository:
>
> ```json
> {
>   "repositories": [{ "type": "vcs", "url": "https://github.com/YOUR_USER/native-http" }],
>   "require": { "nativehttp/client": "^1.0" }
> }
> ```

### Without Composer (cPanel, FTP, shared hosting)

1. Download the repository and upload `src/` and `resources/` to your host.
2. Include the bundled autoloader:

```php
require __DIR__ . '/src/autoload.php';
```

Step-by-step guide: [docs/shared-hosting.md](docs/shared-hosting.md).

## Quick start

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use NativeHttp\Client;

$client = new Client(['timeout' => 20]);

// GET
$start = microtime(true);
$response = $client->get('https://httpbin.org/get', [
    'Accept: application/json',
]);

printf("HTTP %d in %.0f ms\n", $response['status'], (microtime(true) - $start) * 1000);
echo $response['body'];

// POST with JSON
$response = $client->request(
    'POST',
    'https://httpbin.org/post',
    ['Content-Type' => 'application/json'],
    json_encode(['hello' => 'world'])
);

$data = json_decode($response['body'], true);
```

## API

### `new Client(array $options = [])`

| Option | Type | Default | Description |
|---|---|---|---|
| `timeout` | `float` | `20.0` | Maximum seconds per request. |
| `verify_peer` | `bool` | `true` | Verify the server certificate. |
| `ca_file` | `?string` | `null` | Path to a CA bundle. When `null`, the system bundle is located. |
| `max_redirects` | `int` | `5` | Redirects to follow (`0` = none). |
| `alpn` | `list<string>` | `['h2', 'http/1.1']` | Protocols offered via ALPN. Force `['http/1.1']` to test the fallback. |
| `header_table_size` | `int` | `65536` | HPACK dynamic table size. |
| `logger` | `?callable` | `null` | `fn(string $message)` to trace the handshake and transport. |

### `get(string $url, array $headers = []): array`

Shortcut for `request('GET', ...)`.

### `request(string $method, string $url, array $headers = [], ?string $body = null): array`

Headers are accepted in two shapes:

```php
['Accept: application/json', 'X-Key: value']     // "Name: value" list
['Accept' => 'application/json', 'X-Key' => 'value']  // map
```

Always returns:

```php
[
    'status'       => 200,              // int
    'body'         => '...',            // string, already decompressed
    'headers'      => ['content-type' => 'application/json', ...],  // lower-case keys
    'http_version' => '2',              // '2' or '1.1'
    'url'          => 'https://...',    // final URL after redirects
]
```

A `404` does **not** throw: it is a valid response. Check `status`.

### Exceptions

| Exception | When |
|---|---|
| `InvalidArgumentException` | Invalid URL, scheme other than `https`, malformed header or header containing line breaks, invalid options. |
| `NativeHttp\Exception\TlsException` | Connection failure, handshake error, untrusted certificate, hostname mismatch, TLS alert or timeout. |
| `NativeHttp\Exception\HttpException` | Malformed HTTP/2 or HTTP/1.1 response, reset stream, unreadable compression. |

Both extend `RuntimeException`; `InvalidArgumentException` extends
`LogicException`, as usual in PHP.

### Default headers

Unless overridden, the client sends the headers of a Chrome 152 `fetch` request:

```
sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
upgrade-insecure-requests, user-agent,
accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest,
accept-encoding, accept-language, priority
```

`sec-fetch-site` is computed: `same-origin` when the `Referer`/`Origin` host
matches the target, `cross-site` otherwise, `none` when there is no reference.

## Examples

See [`examples/`](examples/):

| File | Shows |
|---|---|
| [`01-quickstart.php`](examples/01-quickstart.php) | GET request and JSON decoding |
| [`02-headers.php`](examples/02-headers.php) | Headers seen by the server |
| [`03-post-json.php`](examples/03-post-json.php) | POST with a JSON body |
| [`04-redirects.php`](examples/04-redirects.php) | Following or blocking redirects |
| [`05-compression.php`](examples/05-compression.php) | Transparent gzip and deflate |
| [`06-errors.php`](examples/06-errors.php) | Exception handling |
| [`07-fingerprint.php`](examples/07-fingerprint.php) | JA3, JA4 and HTTP/2 fingerprint |
| [`08-cron.php`](examples/08-cron.php) | Cronjob script with locking and logging |
| [`09-media.php`](examples/09-media.php) | Download an authorized direct media URL |
| [`web/index.php`](examples/web/index.php) | Web demo: fetch any URL |

```bash
php examples/01-quickstart.php
php examples/07-fingerprint.php
php examples/09-media.php "https://example.com/video.mp4" video.mp4
```

## How it works

In short: **it does not use PHP's TLS stack**. It opens a plain TCP socket and
speaks the protocol itself.

1. **ClientHello** with Chrome's exact layout: GREASE, SNI, groups (`x25519`,
   `secp256r1`, `secp384r1`), ALPN `h2`, ALPS, `compress_certificate`, and
   padding up to 512 bytes.
2. **TLS 1.3 key schedule**: HKDF-SHA256/384, `c hs traffic` / `s hs traffic`,
   application keys after `Finished`.
3. **Records** encrypted with AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305.
4. **Certificate**: chain and hostname verification plus the server's
   `CertificateVerify` signature, including **RSA-PSS** implemented with
   `gmp`/`bcmath` because OpenSSL does not expose it through PHP.
5. **HTTP/2**: preface, Chrome's SETTINGS, HPACK HEADERS, DATA and flow control
   through WINDOW_UPDATE.
6. **HPACK**: RFC 7541 static table, dynamic table and Huffman decoding.

Technical deep dive: [docs/architecture.md](docs/architecture.md).

## Documentation

- [Architecture](docs/architecture.md): protocol, TLS, HTTP/2 and HPACK internals.
- [Shared hosting](docs/shared-hosting.md): installation and setup on cPanel,
  FTP or other hosting providers.

## Resources

[resources/hpack-tables.php](resources/hpack-tables.php) contains the HPACK static
table and Huffman codes used by the HTTP/2 implementation. It is loaded on
demand by `Hpack.php`; it does not need to be included directly.

## Testing

No dependencies: Composer and PHPUnit are not needed.

```bash
composer test                 # or: php tests/run.php
php tests/run.php --offline   # HPACK and validation only, no network
php tests/run.php hpack http  # only the given groups
```

Groups: `hpack`, `tls`, `http`, `fingerprint`.

The suite includes the official **RFC 7541 appendix C vectors** for HPACK,
certificate validation against `badssl.com`, redirects, compression, and a live
fingerprint check against `tls.peet.ws`. Network tests are retried up to three
times so CI does not fail on a transient DNS or connection error.

The tests do not require PHPUnit or network mocking. PHP 8.3 with GMP passed
the complete suite: 28/28 tests.

## Limitations

- **No ML-KEM.** Chrome 152 advertises the post-quantum group `X25519MLKEM768`
  (extension 17613). This library advertises the extension parameters but does
  not complete the key exchange: implementing ML-KEM-768 in pure PHP is out of
  scope. The JA3 is close to Chrome's but not identical.
- **No TLS session resumption** and no 0-RTT: every request opens a new
  connection. You can reuse the `Client` object, but the handshake cost is paid
  per request.
- **No HTTP/3**, and headers are encoded without Huffman (decoding Huffman works
  fine).
- **No OCSP** validation or revocation checking.
- **HTTPS only.** `http://` is rejected on purpose.
- **One stream per request.** There is no concurrent multiplexing on a single
  connection.

## Project layout

```
native-http/
├── src/
│   ├── Client.php              ← HTTP client (entry point)
│   ├── Tls13Socket.php         ← TLS 1.3 over TCP
│   ├── Hpack.php               ← HPACK compressor/decoder
│   ├── autoload.php            ← autoloader without Composer
│   └── Exception/
│       ├── HttpException.php
│       └── TlsException.php
├── resources/
│   └── hpack-tables.php        ← RFC 7541 static and Huffman tables
├── examples/
│   ├── 01-quickstart.php
│   ├── 02-headers.php
│   ├── 03-post-json.php
│   ├── 04-redirects.php
│   ├── 05-compression.php
│   ├── 06-errors.php
│   ├── 07-fingerprint.php
│   ├── 08-cron.php
│   ├── 09-media.php
│   └── web/index.php           ← browser-based fetch demo
├── tests/
│   └── run.php                 ← HPACK, TLS, HTTP and fingerprint tests
├── docs/
│   ├── architecture.md         ← internal protocol documentation
│   └── shared-hosting.md       ← FTP/cPanel installation guide
├── README.md
├── CHANGELOG.md
├── composer.json
└── LICENSE
```

## License

MIT. See [LICENSE](LICENSE).
