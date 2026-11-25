<?php
declare(strict_types=1);

/**
 * Example 3: POST with a JSON body.
 *
 *   php examples/03-post-json.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

$payload = [
    'name' => 'Ana',
    'message' => 'Hello from pure PHP',
    'tags' => ['php', 'tls13', 'http2'],
];

$response = (new Client(['timeout' => 20]))->request(
    'POST',
    'https://httpbin.org/post',
    ['Content-Type' => 'application/json', 'Accept' => 'application/json'],
    json_encode($payload, JSON_THROW_ON_ERROR)
);

printf("HTTP %d\n", $response['status']);

$data = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
echo "Server received: {$data['data']}\n";
echo "Content-Type: {$data['headers']['Content-Type']}\n";
