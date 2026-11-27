# Installing on cPanel and shared hosting

Step-by-step guide to use NativeHttp without SSH, without Composer and without
compiling anything.

## 1. Check PHP

In cPanel → **MultiPHP Manager**, select your domain and choose **PHP 8.1** or
newer. Click *Apply*.

Then, in **Select PHP Version → Extensions**, make sure these are enabled:

- `openssl` (required)
- `zlib` (required)
- `gmp` (recommended) or, instead, `bcmath`
- `brotli` or `zstd` only if you need those response encodings

Without `openssl` the library cannot work: it provides X25519, AES-GCM and
certificate verification.

## 2. Upload the files

The library is two folders:

```
src/         ← client, TLS, HPACK and autoloader
resources/   ← HPACK tables
```

### Option A: outside `public_html` (recommended)

Keep the code unreachable from the browser:

```
/home/YOUR_ACCOUNT/
├── native-http/
│   ├── src/
│   └── resources/
└── public_html/
    └── my-script.php
```

In `my-script.php`:

```php
require __DIR__ . '/../native-http/src/autoload.php';
```

### Option B: everything inside `public_html`

Valid when your host restricts `open_basedir`:

```
public_html/
├── src/
├── resources/
└── my-script.php
```

```php
require __DIR__ . '/src/autoload.php';
```

> Upload `resources/` **next to** `src/`, keeping the structure: `Hpack.php`
> looks for the tables at `../resources/hpack-tables.php`.

### How to upload

1. cPanel → **File Manager**.
2. Compress `src/` and `resources/` into a ZIP, upload it and use **Extract**.
3. Check permissions: folders `755`, files `644`.

## 3. First test

Create `test.php`:

```php
<?php
declare(strict_types=1);

require __DIR__ . '/src/autoload.php';

use NativeHttp\Client;

header('Content-Type: text/plain; charset=utf-8');

try {
    $r = (new Client(['timeout' => 20]))->get('https://httpbin.org/get');

    echo "HTTP {$r['status']} (version {$r['http_version']})\n";
    echo "TLS handshake: OK\n";
    echo substr($r['body'], 0, 300);
} catch (Throwable $e) {
    http_response_code(500);
    echo get_class($e), ': ', $e->getMessage();
}
```

Open it in the browser: `https://yourdomain.com/test.php`.

It should answer something like:

```
HTTP 200 (version 2)
TLS handshake: OK
{ "args": {}, "headers": { ...
```

If you see `HTTP 200` and `version 2`, everything is set up.

## 4. Using it from a cronjob

cPanel → **Cron Jobs** → *Add New Cron Job*.

Example: every hour, save a JSON document.

```
0 * * * * /usr/local/bin/php /home/YOUR_ACCOUNT/script.php >> /home/YOUR_ACCOUNT/cron.log 2>&1
```

The script must use absolute paths and must not depend on `$_GET`:

```php
<?php
declare(strict_types=1);

require '/home/YOUR_ACCOUNT/native-http/src/autoload.php';

use NativeHttp\Client;

// Replace this URL with your own API.
$r = (new Client(['timeout' => 20]))->get('https://httpbin.org/json');

if ($r['status'] !== 200) {
    fwrite(STDERR, "HTTP {$r['status']}\n");
    exit(1);
}

file_put_contents('/home/YOUR_ACCOUNT/data.json', $r['body']);
exit(0);
```

> **PHP path.** On most cPanel servers it is `/usr/local/bin/php`. If it does
> not exist, ask your provider or check `which php` in *Terminal*. With
> EasyApache it is usually `/opt/cpanel/ea-php83/root/usr/bin/php`.
>
> **The `>>` target** must live in a folder that already exists.

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Blank page or error 500 | `openssl` or `zlib` missing; PHP < 8.1 | Check *MultiPHP Manager* and *Select PHP Version* |
| `Call to undefined function` | Another autoload was loaded, or the path is wrong | Use the absolute path to `src/autoload.php` |
| `Class "NativeHttp\Client" not found` | The autoloader was not included | `require` it before using any class |
| `Could not connect to ...` | The host blocks outbound 443 | Ask your provider to allow outbound HTTPS |
| `TLS: ... unknown_ca` | CA bundle missing or outdated | Set `ca_file` to a fresh bundle |
| `RSA-PSS ... neither gmp nor bcmath` | Both extensions missing | Enable `gmp` (or `bcmath`) |
| `Could not decompress` | The server used `br` or `zstd` | Enable that extension, or stop advertising it |
| 403 on a specific site | Extra defences (CAPTCHA, signed cookies) | Not a library bug |
| Slow, 1–2 s per request | New TLS handshake on every call | Expected behaviour |
| Unknown client option | An option name is misspelled | Use the options listed in the README |
| Malformed redirect or chunk | Server response is incomplete or invalid | Inspect the response and report the server URL |

## 6. Verifying the fingerprint

Upload this script and open it:

```php
<?php
require __DIR__ . '/src/autoload.php';

$r = (new NativeHttp\Client())->get('https://tls.peet.ws/api/all');
$d = json_decode($r['body'], true);

echo 'JA3: ', $d['tls']['ja3'], "\n";
echo 'Akamai h2: ', $d['http2']['akamai_fingerprint'], "\n";
```

You should see:

```
JA3: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-21,29-23-24,0
Akamai h2: 1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
```

If the JA3 starts with `771,4865-4866-4867`, TLS is correct. A different order
means something altered the ClientHello (for example a TLS proxy at the host).
