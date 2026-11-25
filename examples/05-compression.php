<?php
declare(strict_types=1);

/**
 * Example 5: transparent compression (gzip and deflate).
 *
 * The client advertises what it supports and decompresses on its own.
 *
 *   php examples/05-compression.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

$client = new Client(['timeout' => 20]);

foreach (['gzip', 'deflate'] as $codec) {
    $r = $client->get("https://httpbin.org/{$codec}");
    $data = json_decode($r['body'], true, 512, JSON_THROW_ON_ERROR);
    printf(
        "%-8s HTTP %d | Content-Encoding: %-8s | decompressed: %s\n",
        $codec,
        $r['status'],
        $r['headers']['content-encoding'] ?? '-',
        $data[$codec === 'gzip' ? 'gzipped' : 'deflated'] ? 'yes' : 'no'
    );
}
