<?php
declare(strict_types=1);

/**
 * Autoloader for using the library without Composer (shared hosting, FTP).
 *
 *   require __DIR__ . '/src/autoload.php';
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'NativeHttp\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($file)) {
        require $file;
    }
});
