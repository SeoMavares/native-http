<?php
declare(strict_types=1);

/**
 * NativeHttp test runner.
 *
 *   php tests/run.php              # everything
 *   php tests/run.php --offline    # local tests only (no network)
 *   php tests/run.php hpack http   # only the given groups
 *
 * No Composer, no PHPUnit: plain PHP.
 */

require_once __DIR__ . '/../src/autoload.php';

final class TestRunner
{
    /** @var list<array{group: string, name: string, ok: bool, detail: string}> */
    private array $results = [];

    private string $group = '';

    private int $failures = 0;

    public function group(string $name): self
    {
        $this->group = $name;

        return $this;
    }

    /**
     * @param int $attempts retries for tests that depend on the network
     */
    public function check(string $name, callable $test, int $attempts = 1): void
    {
        $ok = false;
        $detail = '';

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            try {
                $result = $test();
                $ok = $result === true || $result === null;
                $detail = is_string($result) ? $result : '';
            } catch (Throwable $error) {
                $ok = false;
                $detail = get_class($error) . ': ' . $error->getMessage();
            }

            if ($ok || $attempt === $attempts) {
                break;
            }
            usleep(700_000);
        }

        if (!$ok) {
            $this->failures++;
        }

        $this->results[] = [
            'group' => $this->group,
            'name' => $name,
            'ok' => $ok,
            'detail' => $detail,
        ];
    }

    public function verdict(): int
    {
        $currentGroup = null;

        foreach ($this->results as $row) {
            if ($row['group'] !== $currentGroup) {
                $currentGroup = $row['group'];
                echo "\n", $currentGroup, "\n", str_repeat('-', 74), "\n";
            }
            printf(
                "  %-52s %s%s\n",
                $row['name'],
                $row['ok'] ? 'OK' : 'FAIL',
                $row['detail'] !== '' ? '  (' . $row['detail'] . ')' : ''
            );
        }

        $total = count($this->results);
        $passed = $total - $this->failures;

        echo "\n", str_repeat('=', 74), "\n";
        printf(
            "%d/%d tests passed%s\n",
            $passed,
            $total,
            $this->failures === 0 ? '' : " - {$this->failures} failure(s)"
        );

        return $this->failures === 0 ? 0 : 1;
    }
}

final class Asserts
{
    public static function same(mixed $expected, mixed $actual, string $message = ''): void
    {
        if ($expected !== $actual) {
            throw new RuntimeException(sprintf(
                '%s expected %s, got %s',
                $message !== '' ? $message . ':' : 'Value',
                self::export($expected),
                self::export($actual)
            ));
        }
    }

    public static function true(bool $condition, string $message = 'condition is false'): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    public static function contains(string $needle, string $haystack, string $message = ''): void
    {
        if (!str_contains($haystack, $needle)) {
            throw new RuntimeException(
                ($message !== '' ? $message . ': ' : '') . "does not contain '{$needle}'"
            );
        }
    }

    public static function throws(string $exception, callable $code, string $message = ''): void
    {
        try {
            $code();
        } catch (Throwable $error) {
            if ($error instanceof $exception) {
                return;
            }
            throw new RuntimeException(
                ($message !== '' ? $message . ': ' : '')
                . "expected {$exception}, got " . get_class($error)
            );
        }

        throw new RuntimeException(
            ($message !== '' ? $message . ': ' : '') . "expected {$exception}, nothing was thrown"
        );
    }

    private static function export(mixed $value): string
    {
        return is_scalar($value) || $value === null
            ? var_export($value, true)
            : gettype($value);
    }
}

$arguments = array_slice($argv, 1);
$offline = in_array('--offline', $arguments, true);
$requestedGroups = array_values(array_filter(
    $arguments,
    static fn(string $argument): bool => !str_starts_with($argument, '-')
));

$runner = new TestRunner();

$shouldRun = static function (string $group) use ($requestedGroups): bool {
    return $requestedGroups === [] || in_array($group, $requestedGroups, true);
};

// ---------------------------------------------------------------------------
// HPACK: official RFC 7541 appendix C test vectors
// ---------------------------------------------------------------------------
if ($shouldRun('hpack')) {
    $runner->group('HPACK (RFC 7541 test vectors)');

    $runner->check('C.3.1 request without Huffman', static function (): void {
        $hpack = new NativeHttp\Hpack();
        $fields = $hpack->decode(hex2bin('828684410f7777772e6578616d706c652e636f6d'));
        Asserts::same(
            [[':method', 'GET'], [':scheme', 'http'], [':path', '/'], [':authority', 'www.example.com']],
            $fields
        );
    });

    $runner->check('C.4.1 request with Huffman', static function (): void {
        $hpack = new NativeHttp\Hpack();
        $fields = $hpack->decode(hex2bin('828684418cf1e3c2e5f23a6ba0ab90f4ff'));
        Asserts::same(
            [[':method', 'GET'], [':scheme', 'http'], [':path', '/'], [':authority', 'www.example.com']],
            $fields
        );
    });

    $runner->check('C.5.1 response with dynamic table', static function (): void {
        $hpack = new NativeHttp\Hpack();
        $fields = $hpack->decode(hex2bin(
            '4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d54'
            . '6e1768747470733a2f2f7777772e6578616d706c652e636f6d'
        ));
        Asserts::same(
            [
                [':status', '302'],
                ['cache-control', 'private'],
                ['date', 'Mon, 21 Oct 2013 20:13:21 GMT'],
                ['location', 'https://www.example.com'],
            ],
            $fields
        );
    });

    $runner->check('encode and decode round trip', static function (): void {
        $original = [
            [':method', 'GET'],
            [':authority', 'example.com'],
            [':scheme', 'https'],
            [':path', '/api/v1/items?page=2'],
            ['accept', 'application/json'],
            ['user-agent', 'NativeHttp/1.0'],
            ['x-custom', 'value with spaces'],
        ];
        $hpack = new NativeHttp\Hpack();
        $block = $hpack->encode($original);
        Asserts::same($original, $hpack->decode($block));
    });

    $runner->check('rejects out-of-range index', static function (): void {
        $hpack = new NativeHttp\Hpack();
        Asserts::throws(RuntimeException::class, static fn() => $hpack->decode("\xff\xff\xff\xff"));
    });
}

// ---------------------------------------------------------------------------
// TLS: handshake, ciphers and certificate validation
// ---------------------------------------------------------------------------
if (!$offline && $shouldRun('tls')) {
    $runner->group('TLS 1.3');

    $runner->check('handshake with ALPN h2', static function (): void {
        $tls = new NativeHttp\Tls13Socket('www.cloudflare.com', 443, ['timeout' => 20]);
        try {
            $tls->connect();
            Asserts::same('h2', $tls->getNegotiatedProtocol());
            Asserts::true($tls->getCipherName() !== '', 'no cipher negotiated');
        } finally {
            $tls->close();
        }
    }, 3);

    $runner->check('rejects a certificate for the wrong host', static function (): void {
        Asserts::throws(
            NativeHttp\Exception\TlsException::class,
            static function (): void {
                $tls = new NativeHttp\Tls13Socket('wrong.host.badssl.com', 443, ['timeout' => 20]);
                try {
                    $tls->connect();
                } finally {
                    $tls->close();
                }
            }
        );
    }, 3);

    $runner->check('rejects a self-signed certificate', static function (): void {
        Asserts::throws(
            NativeHttp\Exception\TlsException::class,
            static function (): void {
                $tls = new NativeHttp\Tls13Socket('self-signed.badssl.com', 443, ['timeout' => 20]);
                try {
                    $tls->connect();
                } finally {
                    $tls->close();
                }
            }
        );
    }, 3);

    $runner->check('application data round trip', static function (): void {
        $tls = new NativeHttp\Tls13Socket('tls.peet.ws', 443, ['timeout' => 20]);
        try {
            $tls->connect();
            $tls->writeApplicationData("GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n");
            $response = '';
            while (!$tls->isClosed()) {
                $chunk = $tls->readApplicationData();
                if ($chunk === '') {
                    break;
                }
                $response .= $chunk;
            }
            Asserts::contains('HTTP/1.1 200', $response, 'unexpected response');
        } finally {
            $tls->close();
        }
    }, 3);
}

// ---------------------------------------------------------------------------
// HTTP/2 through the full client
// ---------------------------------------------------------------------------
if (!$offline && $shouldRun('http')) {
    $runner->group('HTTP (full client)');

    $client = new NativeHttp\Client(['timeout' => 20]);

    $runner->check('GET over HTTP/2 returning JSON', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/get', ['Accept: application/json']);
        Asserts::same(200, $r['status']);
        Asserts::same('2', $r['http_version']);
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        Asserts::same('https://httpbin.org/get', $data['url']);
    }, 3);

    $runner->check('sends browser headers', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/headers');
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        $headers = array_change_key_case($data['headers'], CASE_LOWER);
        Asserts::contains('Chrome/', $headers['user-agent'] ?? '', 'user-agent');
        Asserts::true(array_key_exists('sec-ch-ua', $headers), 'missing sec-ch-ua');
        Asserts::contains('Chromium', $headers['sec-ch-ua'], 'sec-ch-ua');
        Asserts::same('cors', $headers['sec-fetch-mode'] ?? '');
    }, 3);

    $runner->check('POST with a JSON body', static function () use ($client): void {
        $body = json_encode(['hello' => 'world']);
        $r = $client->request('POST', 'https://httpbin.org/post', ['Content-Type' => 'application/json'], $body);
        Asserts::same(200, $r['status']);
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        Asserts::same('{"hello":"world"}', $data['data']);
    }, 3);

    $runner->check('decompresses gzip', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/gzip');
        Asserts::same(200, $r['status']);
        Asserts::same('gzip', $r['headers']['content-encoding'] ?? '');
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        Asserts::true($data['gzipped'] === true, 'was not decompressed');
    }, 3);

    $runner->check('decompresses deflate', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/deflate');
        Asserts::same(200, $r['status']);
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        Asserts::true($data['deflated'] === true, 'was not decompressed');
    }, 3);

    $runner->check('follows redirects', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/redirect/2');
        Asserts::same(200, $r['status']);
        Asserts::same('https://httpbin.org/get', $r['url']);
    }, 3);

    $runner->check('returns 404 without throwing', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/status/404');
        Asserts::same(404, $r['status']);
    }, 3);

    $runner->check('exposes response headers', static function () use ($client): void {
        $r = $client->get('https://httpbin.org/get');
        Asserts::true(isset($r['headers']['content-type']), 'no content-type');
    }, 3);

    $runner->check('HTTP/1.1 fallback when the server does not negotiate h2', static function (): void {
        $http1 = new NativeHttp\Client(['timeout' => 20, 'alpn' => ['http/1.1']]);
        $r = $http1->get('https://httpbin.org/get');
        Asserts::same(200, $r['status']);
        Asserts::same('1.1', $r['http_version']);
    }, 3);
}

if (!$offline && $shouldRun('fingerprint')) {
    $runner->group('Fingerprint (tls.peet.ws)');

    $runner->check('JA3 and HTTP/2 match a browser profile', static function (): void {
        $r = (new NativeHttp\Client(['timeout' => 20]))->get('https://tls.peet.ws/api/all');
        $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
        $ja3 = $data['tls']['ja3'] ?? '';
        Asserts::contains('4865-4866-4867', $ja3, 'TLS 1.3 cipher order');
        Asserts::contains('0-23-65281', $ja3, 'extension order');
        $h2 = $data['http2']['akamai_fingerprint'] ?? '';
        Asserts::contains('1:65536;2:0;3:1000;4:6291456;6:262144', $h2, 'Chrome SETTINGS');
    }, 3);
}

// ---------------------------------------------------------------------------
// Validation and error handling
// ---------------------------------------------------------------------------
$runner->group('Errors and validation');

$runner->check('rejects http:// without TLS', static function (): void {
    Asserts::throws(
        InvalidArgumentException::class,
        static fn() => (new NativeHttp\Client(['timeout' => 5]))->get('http://example.com/')
    );
});

$runner->check('rejects an invalid URL', static function (): void {
    Asserts::throws(
        InvalidArgumentException::class,
        static fn() => (new NativeHttp\Client(['timeout' => 5]))->get('not-a-url')
    );
});

$runner->check('rejects a header with a line break', static function (): void {
    Asserts::throws(
        InvalidArgumentException::class,
        static fn() => (new NativeHttp\Client(['timeout' => 5]))->get('https://example.com/', ['X: a' . "\r\n" . 'B: c'])
    );
});

$runner->check('rejects an invalid header name', static function (): void {
    Asserts::throws(
        InvalidArgumentException::class,
        static fn() => (new NativeHttp\Client(['timeout' => 5]))->get('https://example.com/', ['Bad Name' => 'x'])
    );
});

$runner->check('times out on an unresponsive host', static function (): void {
    Asserts::throws(
        NativeHttp\Exception\TlsException::class,
        static fn() => (new NativeHttp\Client(['timeout' => 2]))->get('https://10.255.255.1/')
    );
});

exit($runner->verdict());
