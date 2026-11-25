#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Example 8: script meant for a cronjob.
 *
 * Fetches a JSON document, stores it atomically and logs the result.
 * A lock file prevents overlapping runs.
 *
 *   php examples/08-cron.php [url] [output_dir]
 *
 * Exit codes: 0 success, 1 network failure, 2 invalid arguments,
 * 3 another run is already in progress.
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;
use NativeHttp\Exception\HttpException;
use NativeHttp\Exception\TlsException;

$url = $argv[1] ?? 'https://httpbin.org/json';
$outputDir = rtrim($argv[2] ?? (__DIR__ . '/../data'), '/');

$parts = parse_url($url);
if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
    fwrite(STDERR, "[cron] the URL must use https\n");
    exit(2);
}

if (!is_dir($outputDir) && !@mkdir($outputDir, 0755, true) && !is_dir($outputDir)) {
    fwrite(STDERR, "[cron] could not create {$outputDir}\n");
    exit(1);
}

$lockFile = sys_get_temp_dir() . '/native-http-cron.lock';
$lock = @fopen($lockFile, 'c');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] another run is already in progress\n");
    exit(3);
}

$stamp = static fn(): string => date('Y-m-d H:i:s');

try {
    $response = (new Client(['timeout' => 20]))->get($url, ['Accept: application/json']);

    if ($response['status'] !== 200) {
        throw new HttpException('HTTP ' . $response['status']);
    }

    $target = $outputDir . '/download.json';
    $temporary = $target . '.tmp';
    if (file_put_contents($temporary, $response['body']) === false || !rename($temporary, $target)) {
        @unlink($temporary);
        throw new HttpException('could not write ' . $target);
    }

    file_put_contents(
        $outputDir . '/cron.log',
        '[' . $stamp() . "] OK {$url} -> {$target} (" . strlen($response['body']) . " bytes)\n",
        FILE_APPEND
    );

    echo '[' . $stamp() . '] saved to ' . $target . "\n";
    exit(0);
} catch (TlsException | HttpException $error) {
    file_put_contents(
        $outputDir . '/cron.log',
        '[' . $stamp() . '] ERROR ' . $error->getMessage() . "\n",
        FILE_APPEND
    );
    fwrite(STDERR, '[' . $stamp() . '] ' . $error->getMessage() . "\n");
    exit(1);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}
