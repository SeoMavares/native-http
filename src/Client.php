<?php
declare(strict_types=1);

namespace NativeHttp;

use InvalidArgumentException;
use NativeHttp\Exception\HttpException;

/** HTTP client with a native TLS 1.3 and HTTP/2 stack. */
final class Client
{
    /** @var array<string, mixed> */
    private array $options;

    /**
     * @param array{
     *   timeout?: float,
     *   verify_peer?: bool,
     *   ca_file?: string|null,
     *   max_redirects?: int,
     *   alpn?: list<string>,
     *   logger?: callable(string): void|null
     * } $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $options + [
            'timeout' => 20.0,
            'verify_peer' => true,
            'ca_file' => null,
            'max_redirects' => 5,
            'alpn' => ['h2', 'http/1.1'],
            'header_table_size' => 65536,
            'logger' => null,
        ];
        $this->validateOptions();
    }

    private function validateOptions(): void
    {
        $known = ['timeout', 'verify_peer', 'ca_file', 'max_redirects', 'alpn', 'header_table_size', 'logger'];
        foreach (array_keys($this->options) as $name) {
            if (!in_array($name, $known, true)) {
                throw new InvalidArgumentException('Unknown client option: ' . $name);
            }
        }
        if (!is_int($this->options['timeout']) && !is_float($this->options['timeout'])) {
            throw new InvalidArgumentException('The timeout option must be numeric.');
        }
        $timeout = (float) $this->options['timeout'];
        if (!is_finite($timeout) || $timeout <= 0) {
            throw new InvalidArgumentException('The timeout option must be greater than zero.');
        }
        if (!is_bool($this->options['verify_peer'])) {
            throw new InvalidArgumentException('The verify_peer option must be boolean.');
        }
        if ($this->options['ca_file'] !== null
            && (!is_string($this->options['ca_file']) || $this->options['ca_file'] === '')) {
            throw new InvalidArgumentException('The ca_file option must be null or a non-empty string.');
        }
        if (!is_int($this->options['max_redirects']) || $this->options['max_redirects'] < 0) {
            throw new InvalidArgumentException('The max_redirects option must be a non-negative integer.');
        }
        if (!is_array($this->options['alpn']) || $this->options['alpn'] === []) {
            throw new InvalidArgumentException('The alpn option must be a non-empty list.');
        }
        foreach ($this->options['alpn'] as $protocol) {
            if (!is_string($protocol) || !in_array($protocol, ['h2', 'http/1.1'], true)) {
                throw new InvalidArgumentException('ALPN protocols must be h2 or http/1.1.');
            }
        }
        if (count(array_unique($this->options['alpn'])) !== count($this->options['alpn'])) {
            throw new InvalidArgumentException('The alpn option cannot contain duplicates.');
        }
        if (!is_int($this->options['header_table_size'])
            || $this->options['header_table_size'] < 0
            || $this->options['header_table_size'] > 16777216) {
            throw new InvalidArgumentException('The header_table_size option must be between 0 and 16777216.');
        }
        if ($this->options['logger'] !== null && !is_callable($this->options['logger'])) {
            throw new InvalidArgumentException('The logger option must be callable or null.');
        }
    }

    /**
     * @param list<string>|array<string, string> $headers
     * @return array{status: int, body: string, headers: array<string, string>, http_version: string, url: string}
     */
    public function get(string $url, array $headers = []): array
    {
        return $this->request('GET', $url, $headers);
    }

    /**
     * @param list<string>|array<string, string> $headers
     * @return array{status: int, body: string, headers: array<string, string>, http_version: string, url: string}
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        $method = strtoupper($method);
        if (preg_match("/^[!#$%&'*+\-.^_`|~0-9A-Z]+$/", $method) !== 1) {
            throw new InvalidArgumentException('Invalid HTTP method: ' . $method);
        }
        $headers = $this->normalizeHeaders($headers);
        $redirects = 0;
        $previousUrl = $url;

        while (true) {
            $this->assertValidHttpsUrl($url);
            $response = $this->sendOnce($method, $url, $headers, $body);

            $location = $response['headers']['location'] ?? null;
            if ($location !== null
                && in_array($response['status'], [301, 302, 303, 307, 308], true)
                && $redirects < (int) $this->options['max_redirects']) {
                if ($response['status'] === 303
                    || ($method === 'POST' && in_array($response['status'], [301, 302], true))) {
                    $method = 'GET';
                    $body = null;
                }
                $url = $this->resolveLocation($url, $location);
                if (!$this->sameOrigin($previousUrl, $url)) {
                    foreach (['authorization', 'cookie', 'proxy-authorization'] as $name) {
                        unset($headers[$name]);
                    }
                }
                $previousUrl = $url;
                $redirects++;
                continue;
            }

            return $response;
        }
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string, headers: array<string, string>, http_version: string, url: string}
     */
    private function sendOnce(string $method, string $url, array $headers, ?string $body): array
    {
        $parts = $this->assertValidHttpsUrl($url);

        $host = $parts['host'];
        $port = (int) ($parts['port'] ?? 443);
        $authority = $host . ($port !== 443 ? ':' . $port : '');
        $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

        $fields = $this->buildHeaderFields($method, $authority, $path, $headers);

        $tls = new Tls13Socket($host, $port, [
            'timeout' => (float) $this->options['timeout'],
            'verify_peer' => (bool) $this->options['verify_peer'],
            'ca_file' => $this->options['ca_file'],
            'alpn' => $this->options['alpn'],
            'logger' => $this->options['logger'],
        ]);

        try {
            $tls->connect();
            $this->log('TLS ok: ' . $tls->getCipherName() . ' / alpn ' . ($tls->getNegotiatedProtocol() ?: 'none'));

            $response = $tls->getNegotiatedProtocol() === 'h2'
                ? $this->http2Exchange($tls, $fields, $body)
                : $this->http1Exchange($tls, $method, $authority, $path, $fields, $body);
        } finally {
            $tls->close();
        }

        $response['url'] = $url;

        return $response;
    }

    /**
     * @param array<string, string> $headers
     * @return list<array{0: string, 1: string}>
     */
    private function buildHeaderFields(string $method, string $authority, string $path, array $headers): array
    {
        $reference = $headers['referer'] ?? $headers['origin'] ?? '';
        $referenceHost = $reference !== '' ? (parse_url($reference, PHP_URL_HOST) ?: '') : '';
        $requestHost = explode(':', $authority)[0];

        $defaults = [
            'sec-ch-ua' => '"Chromium";v="152", "Not?A_Brand";v="24"',
            'sec-ch-ua-mobile' => '?0',
            'sec-ch-ua-platform' => '"Linux"',
            'upgrade-insecure-requests' => '1',
            'user-agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                . 'Chrome/152.0.0.0 Safari/537.36',
            'accept' => '*/*',
            'sec-fetch-site' => $referenceHost === '' ? 'none'
                : ($referenceHost === $requestHost ? 'same-origin' : 'cross-site'),
            'sec-fetch-mode' => 'cors',
            'sec-fetch-dest' => 'empty',
            'accept-encoding' => $this->supportedEncodings(),
            'accept-language' => 'es-ES,es;q=0.9,en;q=0.8',
            'priority' => 'u=1, i',
        ];

        $merged = $defaults;
        foreach ($headers as $name => $value) {
            if ($name !== 'host') {
                $merged[$name] = $value;
            }
        }

        $fields = [
            [':method', $method],
            [':authority', $authority],
            [':scheme', 'https'],
            [':path', $path],
        ];
        foreach ($merged as $name => $value) {
            $fields[] = [$name, $value];
        }

        return $fields;
    }

    private function supportedEncodings(): string
    {
        $encodings = ['gzip', 'deflate'];
        if (function_exists('brotli_uncompress')) {
            $encodings[] = 'br';
        }
        if (function_exists('zstd_uncompress')) {
            $encodings[] = 'zstd';
        }
        return implode(', ', $encodings);
    }

    /**
     * @param list<array{0: string, 1: string}> $fields
     * @return array{status: int, body: string, headers: array<string, string>, http_version: string}
     */
    private function http2Exchange(Tls13Socket $tls, array $fields, ?string $body): array
    {
        $handshake = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            . $this->frame(4, 0, 0, self::settingsPayload())
            . $this->frame(8, 0, 0, pack('N', 15663105));
        $tls->writeApplicationData($handshake);

        $hpack = new Hpack((int) ($this->options['header_table_size'] ?? 65536));
        $block = $hpack->encode($fields);
        $streamId = 1;

        $out = $this->headerFrames($block, $streamId, $body === null);
        if ($body !== null && $body !== '') {
            $chunks = str_split($body, 16384);
            $last = count($chunks) - 1;
            foreach ($chunks as $index => $chunk) {
                $out .= $this->frame(0, $index === $last ? 0x1 : 0x0, $streamId, $chunk);
            }
        } elseif ($body !== null) {
            $out .= $this->frame(0, 0x1, $streamId, '');
        }
        $tls->writeApplicationData($out);

        $buffer = '';
        $pendingBlock = '';
        $status = 0;
        $headers = [];
        $data = '';
        $streamEnded = false;
        $pendingContinuation = false;
        $deadline = microtime(true) + (float) $this->options['timeout'];

        while (!$streamEnded) {
            if (microtime(true) > $deadline) {
                throw new HttpException('Timed out waiting for the HTTP/2 response.');
            }

            $chunk = $tls->readApplicationData();
            if ($chunk === '') {
                if ($tls->isClosed()) {
                    break;
                }
                continue;
            }
            $buffer .= $chunk;

            while (($frame = $this->parseFrame($buffer)) !== null) {
                $type = $frame['type'];
                $flags = $frame['flags'];
                $payload = $frame['payload'];
                $frameStream = $frame['stream'];

                if ($frameStream !== 0 && $frameStream !== $streamId && $type !== 3) {
                    continue;
                }
                if ($pendingContinuation && $type !== 9) {
                    throw new HttpException('HTTP/2 CONTINUATION frame is required.');
                }

                switch ($type) {
                    case 0: // DATA
                        if ($frameStream !== $streamId) {
                            break;
                        }
                        if (($flags & 0x8) !== 0) {
                            if ($payload === '') {
                                throw new HttpException('Invalid padded HTTP/2 DATA frame.');
                            }
                            $padding = ord($payload[0]);
                            if ($padding >= strlen($payload)) {
                                throw new HttpException('Invalid HTTP/2 DATA padding.');
                            }
                            $payload = substr($payload, 1, strlen($payload) - $padding - 1);
                        }
                        if ($payload !== '') {
                            $data .= $payload;
                            $size = pack('N', strlen($payload));
                            $tls->writeApplicationData(
                                $this->frame(8, 0, 0, $size) . $this->frame(8, 0, $frame['stream'], $size)
                            );
                        }
                        if (($flags & 0x1) !== 0) {
                            $streamEnded = true;
                        }
                        break;

                    case 1: // HEADERS
                        if ($frameStream !== $streamId) {
                            break;
                        }
                        if (($flags & 0x8) !== 0) {
                            if ($payload === '') {
                                throw new HttpException('Invalid padded HTTP/2 HEADERS frame.');
                            }
                            $padding = ord($payload[0]);
                            if ($padding >= strlen($payload)) {
                                throw new HttpException('Invalid HTTP/2 HEADERS padding.');
                            }
                            $payload = substr($payload, 1, strlen($payload) - $padding - 1);
                        }
                        if (($flags & 0x20) !== 0) {
                            if (strlen($payload) < 5) {
                                throw new HttpException('Invalid HTTP/2 HEADERS priority.');
                            }
                            $payload = substr($payload, 5);
                        }
                        $pendingBlock .= $payload;
                        if (($flags & 0x4) !== 0) {
                            [$status, $headers] = $this->decodeHeaderBlock($hpack, $pendingBlock, $status, $headers);
                            $pendingBlock = '';
                        } else {
                            $pendingContinuation = true;
                        }
                        if (($flags & 0x1) !== 0) {
                            $streamEnded = true;
                        }
                        break;

                    case 9: // CONTINUATION
                        if ($frameStream !== $streamId || !$pendingContinuation) {
                            throw new HttpException('Unexpected HTTP/2 CONTINUATION frame.');
                        }
                        $pendingBlock .= $payload;
                        if (($flags & 0x4) !== 0) {
                            [$status, $headers] = $this->decodeHeaderBlock($hpack, $pendingBlock, $status, $headers);
                            $pendingBlock = '';
                            $pendingContinuation = false;
                        }
                        break;

                    case 4: // SETTINGS
                        if ($frameStream !== 0) {
                            throw new HttpException('Invalid HTTP/2 SETTINGS frame stream.');
                        }
                        if (($flags & 0x1) === 0) {
                            if (strlen($payload) % 6 !== 0) {
                                throw new HttpException('Invalid HTTP/2 SETTINGS payload.');
                            }
                            $tls->writeApplicationData($this->frame(4, 0x1, 0, ''));
                        }
                        break;

                    case 6: // PING
                        if (($flags & 0x1) === 0) {
                            $tls->writeApplicationData($this->frame(6, 0x1, 0, $payload));
                        }
                        break;

                    case 8: // WINDOW_UPDATE
                        break;

                    case 2: // PRIORITY
                        break;

                    case 5: // PUSH_PROMISE
                        throw new HttpException('Unexpected HTTP/2 PUSH_PROMISE frame.');

                    case 3: // RST_STREAM
                        if ($frameStream === $streamId) {
                            throw new HttpException('The server reset the HTTP/2 stream (RST_STREAM).');
                        }
                        break;

                    case 7: // GOAWAY
                        $streamEnded = true;
                        break;

                    default:
                        break;
                }
            }
        }

        if ($pendingContinuation) {
            throw new HttpException('Incomplete HTTP/2 header block; CONTINUATION is missing.');
        }
        if ($status === 0) {
            throw new HttpException('HTTP/2 response without a :status pseudo-header.');
        }

        return [
            'status' => $status,
            'body' => $this->decodeContent($data, $headers['content-encoding'] ?? ''),
            'headers' => $headers,
            'http_version' => '2',
        ];
    }

    /**
     * @param list<array{0: string, 1: string}> $fields
     * @return array{status: int, body: string, headers: array<string, string>, http_version: string}
     */
    private function http1Exchange(
        Tls13Socket $tls,
        string $method,
        string $authority,
        string $path,
        array $fields,
        ?string $body
    ): array {
        $request = $method . ' ' . $path . " HTTP/1.1\r\nHost: " . $authority . "\r\n";
        $hasConnection = false;
        foreach ($fields as [$name, $value]) {
            // HTTP/2 pseudo-headers (:method, :scheme...) do not exist in HTTP/1.1.
            if (str_starts_with($name, ':') || $name === 'host' || $name === 'content-length') {
                continue;
            }
            if ($name === 'connection') {
                $hasConnection = true;
            }
            $request .= $name . ': ' . $value . "\r\n";
        }
        if (!$hasConnection) {
            $request .= "Connection: close\r\n";
        }
        if ($body !== null) {
            $request .= 'Content-Length: ' . strlen($body) . "\r\n";
        }
        $request .= "\r\n" . ($body ?? '');

        $tls->writeApplicationData($request);

        $raw = '';
        while (!$tls->isClosed()) {
            $chunk = $tls->readApplicationData();
            if ($chunk === '') {
                break;
            }
            $raw .= $chunk;
        }

        $separator = strpos($raw, "\r\n\r\n");
        if ($separator === false) {
            throw new HttpException('Incomplete HTTP/1.1 response.');
        }
        $head = substr($raw, 0, $separator);
        $payload = substr($raw, $separator + 4);
        $lines = explode("\r\n", $head);
        $statusLineIndex = 0;
        while (isset($lines[$statusLineIndex])
            && preg_match('#^HTTP/1\.[01]\s+100(?:\s|$)#i', $lines[$statusLineIndex]) === 1) {
            $nextSeparator = strpos($payload, "\r\n\r\n");
            if ($nextSeparator === false) {
                throw new HttpException('Incomplete HTTP/1.1 informational response.');
            }
            $head = substr($payload, 0, $nextSeparator);
            $payload = substr($payload, $nextSeparator + 4);
            $lines = explode("\r\n", $head);
            $statusLineIndex = 0;
        }
        if (!preg_match('#^HTTP/1\.[01]\s+(\d{3})(?:\s|$)#', $lines[0], $matches)) {
            throw new HttpException('Invalid HTTP/1.1 status line.');
        }

        $responseHeaders = [];
        foreach (array_slice($lines, 1) as $line) {
            $position = strpos($line, ':');
            if ($position === false) {
                continue;
            }
            $responseHeaders[strtolower(trim(substr($line, 0, $position)))] = trim(substr($line, $position + 1));
        }

        if (isset($responseHeaders['transfer-encoding'])
            && stripos($responseHeaders['transfer-encoding'], 'chunked') !== false) {
            $payload = $this->decodeChunked($payload);
        } elseif (isset($responseHeaders['content-length'])) {
            $payload = substr($payload, 0, (int) $responseHeaders['content-length']);
        }

        return [
            'status' => (int) $matches[1],
            'body' => $this->decodeContent($payload, $responseHeaders['content-encoding'] ?? ''),
            'headers' => $responseHeaders,
            'http_version' => '1.1',
        ];
    }

    /**
     * @param array<string, string> $headers
     * @return array{0: int, 1: array<string, string>}
     */
    private function decodeHeaderBlock(Hpack $hpack, string $block, int $status, array $headers): array
    {
        foreach ($hpack->decode($block) as [$name, $value]) {
            if ($name === ':status') {
                $status = (int) $value;
                continue;
            }
            if (str_starts_with($name, ':')) {
                continue;
            }
            $headers[$name] = isset($headers[$name]) ? $headers[$name] . ', ' . $value : $value;
        }

        return [$status, $headers];
    }

    private function decodeContent(string $body, string $encoding): string
    {
        $encoding = strtolower(trim($encoding));
        if ($encoding === '' || $encoding === 'identity') {
            return $body;
        }

        foreach (array_reverse(array_map('trim', explode(',', $encoding))) as $codec) {
            $body = match ($codec) {
                'gzip', 'x-gzip' => $this->decompressGzip($body),
                'deflate' => $this->decompressDeflate($body),
                'br' => $this->decompressBrotli($body),
                'zstd' => $this->decompressZstd($body),
                default => throw new HttpException('Unsupported content encoding: ' . $codec),
            };
        }

        return $body;
    }

    private function decompressGzip(string $body): string
    {
        $decoded = @gzdecode($body);
        if ($decoded === false) {
            throw new HttpException('Could not decompress a gzip response.');
        }
        return $decoded;
    }

    private function decompressDeflate(string $body): string
    {
        $decoded = @gzinflate($body);
        if ($decoded === false) {
            $decoded = @gzuncompress($body);
        }
        if ($decoded === false) {
            throw new HttpException('Could not decompress a deflate response.');
        }
        return $decoded;
    }

    private function decompressBrotli(string $body): string
    {
        if (!function_exists('brotli_uncompress')) {
            throw new HttpException('The response uses brotli and the brotli extension is not installed.');
        }
        $decoded = @brotli_uncompress($body);
        if ($decoded === false) {
            throw new HttpException('Could not decompress a brotli response.');
        }
        return $decoded;
    }

    private function decompressZstd(string $body): string
    {
        if (!function_exists('zstd_uncompress')) {
            throw new HttpException('The response uses zstd and the zstd extension is not installed.');
        }
        $decoded = @zstd_uncompress($body);
        if ($decoded === false) {
            throw new HttpException('Could not decompress a zstd response.');
        }
        return $decoded;
    }

    private function decodeChunked(string $body): string
    {
        $decoded = '';
        $offset = 0;
        $length = strlen($body);

        while ($offset < $length) {
            $lineEnd = strpos($body, "\r\n", $offset);
            if ($lineEnd === false) {
                throw new HttpException('Incomplete HTTP/1.1 chunk size.');
            }
            $sizeLine = trim(explode(';', substr($body, $offset, $lineEnd - $offset))[0]);
            if (preg_match('/^[0-9A-Fa-f]+$/', $sizeLine) !== 1) {
                throw new HttpException('Invalid HTTP/1.1 chunk size.');
            }
            $size = hexdec($sizeLine);
            $offset = $lineEnd + 2;
            if ($size === 0) {
                if (substr($body, $offset, 2) === "\r\n") {
                    $offset += 2;
                }
                if ($offset < $length) {
                    while ($offset < $length) {
                        $trailerEnd = strpos($body, "\r\n", $offset);
                        if ($trailerEnd === false) {
                            throw new HttpException('Incomplete HTTP/1.1 trailer.');
                        }
                        if ($trailerEnd === $offset) {
                            return $decoded;
                        }
                        $offset = $trailerEnd + 2;
                    }
                }
                return $decoded;
            }
            if ($offset + $size + 2 > $length) {
                throw new HttpException('Incomplete HTTP/1.1 chunk.');
            }
            $decoded .= substr($body, $offset, (int) $size);
            $offset += (int) $size + 2;
        }

        throw new HttpException('Incomplete HTTP/1.1 chunked response.');
    }

    private static function settingsPayload(): string
    {
        return pack('nNnNnNnNnN', 1, 65536, 2, 0, 3, 1000, 4, 6291456, 6, 262144);
    }

    private function headerFrames(string $block, int $streamId, bool $endStream): string
    {
        $flags = $endStream ? 0x1 : 0x0;
        $max = 16384;

        if (strlen($block) <= $max) {
            return $this->frame(1, $flags | 0x4, $streamId, $block);
        }

        $out = $this->frame(1, $flags, $streamId, substr($block, 0, $max));
        $block = substr($block, $max);
        while (strlen($block) > $max) {
            $out .= $this->frame(9, 0x0, $streamId, substr($block, 0, $max));
            $block = substr($block, $max);
        }

        return $out . $this->frame(9, 0x4, $streamId, $block);
    }

    private function frame(int $type, int $flags, int $streamId, string $payload): string
    {
        return substr(pack('N', strlen($payload)), 1)
            . chr($type)
            . chr($flags)
            . pack('N', $streamId & 0x7fffffff)
            . $payload;
    }

    /**
     * @return array{type: int, flags: int, stream: int, payload: string}|null
     */
    private function parseFrame(string &$buffer): ?array
    {
        if (strlen($buffer) < 9) {
            return null;
        }
        $length = (ord($buffer[0]) << 16) | (ord($buffer[1]) << 8) | ord($buffer[2]);
        if (strlen($buffer) < 9 + $length) {
            return null;
        }
        $rawStream = unpack('N', substr($buffer, 5, 4))[1];
        if (($rawStream & 0x80000000) !== 0) {
            throw new HttpException('Invalid reserved bit in HTTP/2 frame stream identifier.');
        }

        $frame = [
            'type' => ord($buffer[3]),
            'flags' => ord($buffer[4]),
            'stream' => unpack('N', substr($buffer, 5, 4))[1] & 0x7fffffff,
            'payload' => substr($buffer, 9, $length),
        ];
        $buffer = substr($buffer, 9 + $length);

        return $frame;
    }

    /**
     * @param list<string>|array<string, string> $headers
     * @return array<string, string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            if (is_int($name)) {
                $position = strpos((string) $value, ':');
                if ($position === false) {
                    throw new InvalidArgumentException('Each header must be a "Name: value" string.');
                }
                $name = substr((string) $value, 0, $position);
                $value = substr((string) $value, $position + 1);
            }
            $name = strtolower(trim((string) $name));
            $value = trim((string) $value);
            if (preg_match("/^[a-z0-9!#$%&'*+.^_`|~-]+$/", $name) !== 1) {
                throw new InvalidArgumentException('Invalid header name: ' . $name . '.');
            }
            if (str_contains($value, "\r") || str_contains($value, "\n")) {
                throw new InvalidArgumentException('Header "' . $name . '" contains line breaks.');
            }
            $normalized[$name] = $value;
        }

        return $normalized;
    }

    private function resolveLocation(string $base, string $location): string
    {
        $location = trim($location);
        if ($location === '') {
            throw new InvalidArgumentException('Redirect Location is empty.');
        }
        if (str_contains($location, "\r") || str_contains($location, "\n")) {
            throw new InvalidArgumentException('Redirect Location contains line breaks.');
        }
        $baseParts = parse_url($base);
        if ($baseParts === false) {
            throw new InvalidArgumentException('Invalid base URL.');
        }
        $scheme = strtolower($baseParts['scheme'] ?? 'https');
        $host = $baseParts['host'] ?? '';
        $port = isset($baseParts['port']) ? ':' . $baseParts['port'] : '';

        if (preg_match('#^([a-z][a-z0-9+.-]*):#i', $location, $match) === 1) {
            $resolved = $location;
        } elseif (str_starts_with($location, '//')) {
            $resolved = $scheme . ':' . $location;
        } else {
            $origin = $scheme . '://' . $host . $port;
            $basePath = $baseParts['path'] ?? '/';
            $hash = strpos($location, '#');
            if ($hash !== false) {
                $location = substr($location, 0, $hash);
            }
            if (str_starts_with($location, '/')) {
                $path = $location;
            } elseif (str_starts_with($location, '?')) {
                $parts = explode('?', $basePath, 2);
                $path = $parts[0] . $location;
            } else {
                $slash = strrpos($basePath, '/');
                $path = substr($basePath, 0, $slash === false ? 0 : $slash + 1) . $location;
            }
            $resolved = $origin . $this->normalizeUrlPath($path);
        }

        $parts = $this->assertValidHttpsUrl($resolved);
        $resolved = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $resolved .= ':' . $parts['port'];
        }
        $resolved .= $parts['path'] ?? '/';
        if (isset($parts['query'])) {
            $resolved .= '?' . $parts['query'];
        }
        return $resolved;
    }

    private function normalizeUrlPath(string $path): string
    {
        $query = '';
        $question = strpos($path, '?');
        if ($question !== false) {
            $query = substr($path, $question);
            $path = substr($path, 0, $question);
        }
        $trailingSlash = str_ends_with($path, '/');
        $output = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($output);
                continue;
            }
            $output[] = $segment;
        }
        $normalized = '/' . implode('/', $output);
        if ($trailingSlash && $normalized !== '/') {
            $normalized .= '/';
        }
        return $normalized . $query;
    }

    private function sameOrigin(string $first, string $second): bool
    {
        $a = parse_url($first);
        $b = parse_url($second);
        if ($a === false || $b === false) {
            return false;
        }
        $aPort = (int) ($a['port'] ?? 443);
        $bPort = (int) ($b['port'] ?? 443);
        return strtolower($a['scheme']) === strtolower($b['scheme'])
            && strtolower($a['host']) === strtolower($b['host'])
            && $aPort === $bPort;
    }

    /**
     * @return array<string, int|string>
     */
    private function assertValidHttpsUrl(string $url): array
    {
        if (str_contains($url, "\r") || str_contains($url, "\n")) {
            throw new InvalidArgumentException('Invalid URL: contains line breaks.');
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'], $parts['scheme'])) {
            throw new InvalidArgumentException('Invalid URL: ' . $url);
        }
        if (strtolower($parts['scheme']) !== 'https') {
            throw new InvalidArgumentException('Only HTTPS URLs are supported.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException('URLs containing user or password information are not supported.');
        }
        if (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535)) {
            throw new InvalidArgumentException('Invalid URL port.');
        }
        if ($parts['host'] === '') {
            throw new InvalidArgumentException('Invalid URL host.');
        }
        return $parts;
    }

    private function log(string $message): void
    {
        $logger = $this->options['logger'] ?? null;
        if (is_callable($logger)) {
            $logger($message);
        }
    }
}
