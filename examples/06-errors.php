<?php
declare(strict_types=1);

/**
 * Example 6: error handling.
 *
 *   php examples/06-errors.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;
use NativeHttp\Exception\HttpException;
use NativeHttp\Exception\TlsException;

$client = new Client(['timeout' => 5]);

$cases = [
    'Invalid URL' => 'not-a-url',
    'HTTP instead of HTTPS' => 'http://example.com/',
    'Non-existent host' => 'https://does-not-exist.invalid/',
];

foreach ($cases as $label => $url) {
    try {
        $client->get($url);
        printf("%-26s no error\n", $label);
    } catch (InvalidArgumentException $e) {
        printf("%-26s invalid argument: %s\n", $label, $e->getMessage());
    } catch (TlsException $e) {
        printf("%-26s TLS: %s\n", $label, $e->getMessage());
    } catch (HttpException $e) {
        printf("%-26s HTTP: %s\n", $label, $e->getMessage());
    }
}

// A 404 is not an exception: it is a valid response.
$r = $client->get('https://httpbin.org/status/404');
printf("%-26s HTTP %d\n", 'Missing resource', $r['status']);
