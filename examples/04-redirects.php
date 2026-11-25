<?php
declare(strict_types=1);

/**
 * Example 4: redirects and how to control them.
 *
 *   php examples/04-redirects.php
 */

require_once __DIR__ . '/../src/autoload.php';

use NativeHttp\Client;

// By default up to 5 redirects are followed.
$followed = (new Client(['timeout' => 20]))->get('https://httpbin.org/redirect/3');
printf("Following redirects: HTTP %d at %s\n", $followed['status'], $followed['url']);

// With max_redirects = 0 the first response (302) is returned.
$notFollowed = (new Client(['timeout' => 20, 'max_redirects' => 0]))
    ->get('https://httpbin.org/redirect/3');
printf(
    "Not following: HTTP %d, Location: %s\n",
    $notFollowed['status'],
    $notFollowed['headers']['location'] ?? '(no location)'
);
