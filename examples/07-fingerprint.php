<?php
declare(strict_types=1);

/**
 * Example 7: inspect the TLS and HTTP/2 fingerprint seen by the server.
 *
 *   php examples/07-fingerprint.php
 *
 * Prints the JA3/JA4 values and the HTTP/2 fingerprint (Akamai format).
 * Use it to confirm the handshake matches a modern browser.
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

$response = (new Client(['timeout' => 20]))->get('https://tls.peet.ws/api/all');
$data = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);

echo "JA3:                ", $data['tls']['ja3'] ?? '?', "\n";
echo "JA3 hash:           ", $data['tls']['ja3_hash'] ?? '?', "\n";
echo "JA4:                ", $data['tls']['ja4'] ?? '?', "\n";
echo "HTTP/2 (Akamai):    ", $data['http2']['akamai_fingerprint'] ?? '?', "\n";
echo "User-Agent:         ", $data['user_agent'] ?? '?', "\n";
echo "HTTP version:       ", $data['http_version'] ?? '?', "\n";
