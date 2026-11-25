# Architecture

How NativeHttp works internally. Useful if you plan to modify it, debug it, or
want to understand why it dodges blocks.

```
┌──────────────────────────────────────────────────────┐
│  Client                                              │
│  · browser headers             · redirects           │
│  · gzip/deflate                · URL validation      │
├──────────────────────────────────────────────────────┤
│  Tls13Socket                                         │
│  · ClientHello                 · key schedule        │
│  · encrypted records           · CertificateVerify   │
├──────────────────────────────────────────────────────┤
│  stream_socket_client  (plain TCP, no SSL wrapper)   │
└──────────────────────────────────────────────────────┘
```

## 1. Why the handshake is not left to `ext-openssl`

The extension exposes very little of the TLS hello: you can pick the version,
ALPN and a cipher list, but you **cannot** control:

- the TLS 1.3 cipher order (`TLS_AES_128_GCM_SHA256` first),
- the curves and their order,
- GREASE values,
- the extension order,
- the ClientHello padding.

That is exactly what makes up the *fingerprint* (JA3/JA4). So the handshake is
built by hand and OpenSSL is only used for individual primitives: X25519,
AES-GCM, ChaCha20-Poly1305, certificate verification and RSA-PSS.

## 2. ClientHello

`Tls13Socket::buildClientHello()` assembles the message with Chrome 152's order:

| # | Extension | Content |
|---|---|---|
| 1 | GREASE | random `0x0a0a + 0x1010n` |
| 2 | `server_name` | host, unless it is an IP |
| 3 | `extended_master_secret` | empty |
| 4 | `renegotiation_info` | `00` |
| 5 | `supported_groups` | GREASE, x25519, secp256r1, secp384r1 |
| 6 | `ec_point_formats` | uncompressed |
| 7 | `session_ticket` | empty |
| 8 | `application_layer_protocol_negotiation` | `h2`, `http/1.1` |
| 9 | `status_request` | OCSP stapling |
| 10 | `signature_algorithms` | ECDSA and RSA (PSS and PKCS#1) + GREASE |
| 11 | `signed_certificate_timestamp` | empty |
| 12 | `key_share` | GREASE (1 byte), x25519 |
| 13 | `psk_key_exchange_modes` | `psk_dhe_ke` |
| 14 | `supported_versions` | GREASE, TLS 1.3, TLS 1.2 |
| 15 | `compress_certificate` | zlib |
| 16 | ALPS (`0x44cd`) | list of protocols that carry settings |
| 17 | `padding` | up to 512 bytes |

Cipher suites are offered in this order: GREASE, `1301`, `1302`, `1303`, `c02b`,
`c02f`, `c02c`, `c030`, `cca9`, `cca8`, `c013`, `c014`, `009c`, `009d`, `002f`,
`0035`.

## 3. Key schedule

The RFC 8446 §7.1 schedule is implemented as is:

```
early_secret     = HKDF-Extract(0, 0)
derived          = HKDF-Expand-Label(early_secret, "derived", "", Hash.length)
handshake_secret = HKDF-Extract(derived, ECDHE)
master_secret    = HKDF-Extract(derived2, 0)

c hs traffic / s hs traffic  → handshake keys
c ap traffic / s ap traffic  → application keys
```

`HKDF-Expand-Label` is built by hand (`tls13 <label>`), because `hash_hkdf()`
does not allow the TLS label prefix.

The *transcript* is the concatenation of every handshake message; its hash is
recomputed at each point (ClientHello+ServerHello, then with
EncryptedExtensions/Certificate/CertificateVerify). Keeping the transcript
rather than a running hash costs a bit of CPU and makes the code much easier to
audit.

## 4. Records

Each record is:

```
header  = 0x17 0x03 0x03 <2-byte length>
nonce   = iv XOR seq (12 bytes, seq right-aligned)
payload = AEAD(key, nonce, plaintext || inner_type, aad = header)
```

The real content type (handshake, application_data, alert) travels encrypted
inside the record, as TLS 1.3 requires. Trailing padding is stripped when
reading.

Post-handshake `KeyUpdate` messages are handled: the new key is derived with the
`traffic upd` label and the sequence counter is reset.

## 5. Certificate verification

Three independent checks:

1. **Chain**: `openssl_x509_checkpurpose()` against the system bundle plus the
   intermediate certificates sent by the server (written to a temporary file
   that is always removed in `finally`).
2. **Hostname**: `subjectAltName` entries (DNS and IP) are compared; a single
   level wildcard is accepted (`*.example.com` covers `a.example.com`, not
   `a.b.example.com`).
3. **Signature**: `CertificateVerify`. The signed content is
   `64 spaces + "TLS 1.3, server CertificateVerify\0" + hash(transcript)`.

ECDSA and RSA PKCS#1 are delegated to `openssl_verify()`. For **RSA-PSS** the
PHP extension does not expose the variant, so EMSA-PSS is implemented in full:

```
m = RSAEP(signature)  → EM
EM = maskedDB || H || 0xbc
DB = maskedDB XOR MGF1(H)
DB = PS(0x00) || 0x01 || salt
H' = Hash(0x00*8 || Hash(M) || salt)
valid if H == H'
```

Modular exponentiation uses `gmp_powm()` and falls back to `bcpowmod()`.

## 6. HTTP/2

On connect the preface and Chrome's SETTINGS are sent:

```
HEADER_TABLE_SIZE=65536  ENABLE_PUSH=0  MAX_CONCURRENT_STREAMS=1000
INITIAL_WINDOW_SIZE=6291456  MAX_HEADER_LIST_SIZE=262144
```

followed by a connection `WINDOW_UPDATE` of `15663105`. The resulting Akamai
fingerprint is:

```
1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
```

Each request uses stream 1:

1. `HEADERS` with HPACK (end of stream when there is no body).
2. `DATA` in 16 KB chunks when there is a body.
3. Frames are read: `HEADERS` (with `CONTINUATION` when needed), `DATA`
   (padding stripped), `SETTINGS` (ACK is sent), `PING` (answered),
   `WINDOW_UPDATE`.
4. On receiving `DATA`, window credit is returned with two `WINDOW_UPDATE`
   frames (connection and stream) so large responses never stall.
5. `RST_STREAM` and `GOAWAY` are treated as errors.

## 7. HPACK

- **Sending**: static table (full index when name and value match, name index
  when only the name matches) and literals without Huffman coding.
- **Receiving**: all four representations (indexed, literal with incremental
  indexing, literal never indexed, dynamic table size update) plus Huffman.
- The Huffman table lives in `resources/hpack-tables.php` and was generated
  from the RFC 7541 text (257 codes, including EOS).

## 8. Compression

`Content-Encoding` is processed in reverse order (it can be a chain):

| Codec | Function |
|---|---|
| `gzip` | `gzdecode()` |
| `deflate` | `gzinflate()`, then `gzuncompress()` as fallback |
| `br` | `brotli_uncompress()` when the extension exists |
| `zstd` | `zstd_uncompress()` when the extension exists |

`accept-encoding` advertises only what can actually be decompressed, so the
client never asks for something it cannot read.

## 9. Design decisions

- **One file per responsibility**, no framework and no dependency injection:
  easy to upload over FTP.
- **Arrays instead of response objects**: `$r['status']` is trivial to use and
  avoids versioning value classes.
- **Exceptions for errors, `status` for HTTP codes**: a 404 is data, not a
  program error.
- **`stream_socket_client` with `tcp://`** on purpose: TLS is the library's job.
- **No global state**: each `Client` is independent and safe under PHP-FPM
  concurrency.
