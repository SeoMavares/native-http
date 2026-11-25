<?php
declare(strict_types=1);

/**
 * Web demo: fetch any URL from the browser.
 *
 * Upload this folder together with src/ and resources/ (or run `php -S`),
 * then open index.php. It asks for an HTTPS URL and shows the status,
 * response headers and a preview of the body.
 */

// Works from the repository layout (../../src) and from a hosting layout
// where src/ sits next to this page.
$autoload = null;
foreach ([__DIR__ . '/../../src/autoload.php', __DIR__ . '/../src/autoload.php', __DIR__ . '/src/autoload.php'] as $candidate) {
    if (is_file($candidate)) {
        $autoload = $candidate;
        break;
    }
}
if ($autoload === null) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit("src/autoload.php not found. Upload the src/ folder next to this page.\n");
}
require_once $autoload;

use NativeHttp\Client;
use NativeHttp\Exception\HttpException;
use NativeHttp\Exception\TlsException;

/** @param mixed $value */
function h($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$url = isset($_GET['url']) ? trim((string) $_GET['url']) : 'https://httpbin.org/get';
$result = null;
$error = null;
$milliseconds = 0;

if (isset($_GET['url'])) {
    if (filter_var($url, FILTER_VALIDATE_URL) === false || parse_url($url, PHP_URL_SCHEME) !== 'https') {
        $error = 'The URL must start with https:// and be valid.';
    } else {
        $start = microtime(true);
        try {
            $result = (new Client(['timeout' => 20]))->get($url, ['Accept: */*']);
        } catch (TlsException | HttpException $failure) {
            $error = $failure->getMessage();
        }
        $milliseconds = (microtime(true) - $start) * 1000;
    }
}

$shortBody = '';
$validJson = false;
if ($result !== null) {
    $shortBody = strlen($result['body']) > 4000
        ? substr($result['body'], 0, 4000) . "\n... (truncated)"
        : $result['body'];
    $validJson = json_decode($result['body']) !== null;
}
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NativeHttp · demo</title>
<style>
    :root { color-scheme: dark; }
    body {
        margin: 0; padding: 32px 20px; background: #0f1115; color: #e6e8eb;
        font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    main { max-width: 960px; margin: 0 auto; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    p.lead { color: #9aa4b2; margin: 0 0 22px; }
    form { display: flex; gap: 10px; margin-bottom: 22px; }
    input[type=url] {
        flex: 1; padding: 11px 13px; border-radius: 9px; border: 1px solid #2a3240;
        background: #12161d; color: #e6e8eb; font-size: 14px;
    }
    button {
        padding: 11px 20px; border-radius: 9px; border: 1px solid #35507a;
        background: #1b2a44; color: #cfe0ff; font-size: 14px; cursor: pointer;
    }
    button:hover { background: #22304a; }
    section {
        background: #161a21; border: 1px solid #242a34; border-radius: 12px;
        padding: 16px 18px; margin-bottom: 16px;
    }
    h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .06em; color: #8fa0b5; margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #222833; vertical-align: top; font-size: 13.5px; }
    th { color: #8fa0b5; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    pre {
        margin: 0; padding: 12px 14px; background: #0c0f14; border: 1px solid #1e2530;
        border-radius: 8px; overflow-x: auto; font-size: 12.5px; line-height: 1.55;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #cbd5e1;
        white-space: pre-wrap; word-break: break-word;
    }
    .pill {
        display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
        background: #14351f; color: #7ee2a8; border: 1px solid #1d4d2d;
    }
    .pill.bad { background: #3a1414; color: #ff9b9b; border-color: #5a1d1d; }
    .muted { color: #8fa0b5; font-size: 13px; }
    .error { color: #ffb4b4; }
</style>
</head>
<body>
<main>
    <h1>NativeHttp · demo</h1>
    <p class="lead">
        A real HTTPS request made by PHP, with its own TLS 1.3 and HTTP/2 stack.
        No curl, no external extensions.
    </p>

    <form method="get">
        <input type="url" name="url" value="<?= h($url) ?>" placeholder="https://example.com" required>
        <button type="submit">Fetch</button>
    </form>

    <?php if ($error !== null): ?>
        <section>
            <h2>Error</h2>
            <p class="error"><?= h($error) ?></p>
        </section>
    <?php endif; ?>

    <?php if ($result !== null): ?>
        <section>
            <h2>Response</h2>
            <p>
                <span class="pill <?= $result['status'] < 400 ? '' : 'bad' ?>">
                    HTTP <?= (int) $result['status'] ?>
                </span>
                <span class="muted">
                    &middot; HTTP/<?= h($result['http_version']) ?>
                    &middot; <?= number_format(strlen($result['body'])) ?> bytes
                    &middot; <?= number_format($milliseconds, 0) ?> ms
                    <?= $validJson ? ' &middot; valid JSON' : '' ?>
                </span>
            </p>
        </section>

        <section>
            <h2>Response headers</h2>
            <table>
                <tbody>
                <?php foreach ($result['headers'] as $name => $value): ?>
                    <tr>
                        <th style="width:220px"><?= h($name) ?></th>
                        <td><?= h($value) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Body</h2>
            <pre><?= h($shortBody) ?></pre>
        </section>
    <?php endif; ?>
</main>
</body>
</html>
