<?php
declare(strict_types=1);

/**
 * Example 1: GET request and JSON decoding.
 *
 *   php examples/01-quickstart.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

$client = new Client(['timeout' => 20]);

$response = $client->get('https://httpbin.org/get', [
    'Accept: application/json',
]);

echo "HTTP {$response['status']} (version {$response['http_version']})\n";

if ($response['status'] === 200) {
    $data = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
    echo "Requested URL: {$data['url']}\n";
    echo "Origin IP: {$data['origin']}\n";
}
