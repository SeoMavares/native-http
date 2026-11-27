<?php
declare(strict_types=1);

/**
 * Example 9: save an authorized direct media URL.
 *
 *   php examples/09-media.php "https://example.com/video.mp4" video.mp4
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;
use NativeHttp\Exception\HttpException;
use NativeHttp\Exception\TlsException;

$url = $argv[1] ?? '';
$output = $argv[2] ?? 'download.bin';

if ($url === '') {
    fwrite(STDERR, "Usage: php examples/09-media.php <https-url> [output-file]\n");
    exit(1);
}

try {
    $response = (new Client(['timeout' => 60]))->get($url);
    if ($response['status'] < 200 || $response['status'] >= 300) {
        fwrite(STDERR, "HTTP {$response['status']}\n");
        exit(1);
    }
    if (@file_put_contents($output, $response['body']) === false) {
        throw new RuntimeException("Could not write {$output}");
    }
    printf("Saved %d bytes to %s\n", strlen($response['body']), $output);
} catch (InvalidArgumentException | TlsException | HttpException | RuntimeException $error) {
    fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . "\n");
    exit(1);
}
