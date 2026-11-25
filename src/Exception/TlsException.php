<?php
declare(strict_types=1);

namespace NativeHttp\Exception;

use RuntimeException;

/**
 * Handshake or TLS record layer error.
 */
final class TlsException extends RuntimeException
{
}
