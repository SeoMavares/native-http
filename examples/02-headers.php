<?php
declare(strict_types=1);

/**
 * Example 2: inspect the headers the server actually receives.
 *
 * Useful to verify the client presents itself as a browser.
 *
 *   php examples/02-headers.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

$response = (new Client(['timeout' => 20]))->get('https://httpbin.org/headers');
$data = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);

echo "Headers received by the server:\n\n";
foreach ($data['headers'] as $name => $value) {
    printf("  %-26s %s\n", $name, $value);
}
