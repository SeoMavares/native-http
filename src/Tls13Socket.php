<?php
declare(strict_types=1);

namespace NativeHttp;

use NativeHttp\Exception\TlsException;

/** TLS 1.3 client on a plain TCP stream. */
final class Tls13Socket
{
    private const HRR_RANDOM = "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91"
        . "\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C";

    private const ALERTS = [
        0 => 'close_notify', 10 => 'unexpected_message', 20 => 'bad_record_mac',
        22 => 'record_overflow', 40 => 'handshake_failure', 42 => 'bad_certificate',
        43 => 'unsupported_certificate', 44 => 'certificate_revoked', 45 => 'certificate_expired',
        46 => 'certificate_unknown', 47 => 'illegal_parameter', 48 => 'unknown_ca',
        49 => 'access_denied', 50 => 'decode_error', 51 => 'decrypt_error',
        70 => 'protocol_version', 71 => 'insufficient_security', 80 => 'internal_error',
        86 => 'inappropriate_fallback', 90 => 'user_canceled', 109 => 'missing_extension',
        110 => 'unsupported_extension', 112 => 'unrecognized_name',
        113 => 'bad_certificate_status_response', 116 => 'certificate_required',
        120 => 'no_application_protocol',
    ];

    /** @var resource|null */
    private $socket = null;

    /** @var \OpenSSLAsymmetricKey|resource|null */
    private $x25519Key = null;

    private string $host;

    private int $port;

    private float $timeout;

    private bool $verifyPeer;

    private ?string $caFile;

    private string $verifyHost;

    /** @var list<string> */
    private array $alpn;

    /** @var callable(string): void|null */
    private $logger;

    private string $handshakeBuffer = '';

    private string $postHandshakeBuffer = '';

    private string $handshakeTranscript = '';

    private string $cipher = '';

    private string $hashAlgo = 'sha256';

    private int $hashLength = 32;

    private int $keyLength = 16;

    private string $clientHandshakeSecret = '';

    private string $serverHandshakeSecret = '';

    private string $clientAppSecret = '';

    private string $serverAppSecret = '';

    private string $masterSecretSeed = '';

    private string $readKey = '';

    private string $readIv = '';

    private string $writeKey = '';

    private string $writeIv = '';

    private int $readSequence = 0;

    private int $writeSequence = 0;

    private string $x25519Public = '';

    private string $leafCertificatePem = '';

    private bool $closed = false;

    private string $negotiatedProtocol = '';

    /** @var array<string, mixed> */
    private array $peerCertificate = [];

    /**
     * @param array{
     *   timeout?: float,
     *   verify_peer?: bool,
     *   ca_file?: string|null,
     *   server_name?: string|null,
     *   alpn?: list<string>,
     *   logger?: callable(string): void|null
     * } $options
     */
    public function __construct(string $host, int $port = 443, array $options = [])
    {
        $this->host = $host;
        $this->port = $port;
        $this->timeout = (float) ($options['timeout'] ?? 20);
        $this->verifyPeer = (bool) ($options['verify_peer'] ?? true);
        $this->caFile = isset($options['ca_file']) && $options['ca_file'] !== ''
            ? $options['ca_file']
            : self::locateCaBundle();
        $this->verifyHost = $options['server_name'] ?? $host;
        $this->alpn = $options['alpn'] ?? ['h2', 'http/1.1'];
        $this->logger = $options['logger'] ?? null;
    }

    public function getNegotiatedProtocol(): string
    {
        return $this->negotiatedProtocol;
    }

    /**
     * @return array<string, mixed>
     */
    public function getPeerCertificate(): array
    {
        return $this->peerCertificate;
    }

    public function getCipherName(): string
    {
        return $this->cipher;
    }

    public function connect(): void
    {
        $this->openTransport();
        $this->log('TCP conectado a ' . $this->host . ':' . $this->port);

        [$this->x25519Public, $this->x25519Key] = self::generateX25519();

        $clientHello = $this->buildClientHello();
        $this->handshakeTranscript = $clientHello;
        $this->writePlainRecord(22, $clientHello);
        $this->log('ClientHello enviado (' . strlen($clientHello) . ' bytes)');

        $serverHello = $this->nextHandshakeMessage();
        if ($serverHello['type'] !== 2) {
            throw new TlsException('Expected ServerHello but received handshake message ' . $serverHello['type'] . '.');
        }
        if (substr($serverHello['body'], 2, 32) === self::HRR_RANDOM) {
            throw new TlsException('The server requested a HelloRetryRequest (group not offered); not supported.');
        }

        $this->handshakeTranscript .= $serverHello['raw'];
        $this->processServerHello($serverHello['body']);
        $this->log('ServerHello: cipher=' . $this->cipher);

        while (true) {
            $message = $this->nextHandshakeMessage();
            switch ($message['type']) {
                case 8: // EncryptedExtensions
                    $this->processEncryptedExtensions($message['body']);
                    $this->handshakeTranscript .= $message['raw'];
                    break;
                case 25: // CompressedCertificate
                    $this->processCompressedCertificate($message['body']);
                    $this->handshakeTranscript .= $message['raw'];
                    break;
                case 11: // Certificate
                    $this->processCertificate($message['body']);
                    $this->handshakeTranscript .= $message['raw'];
                    break;
                case 15: // CertificateVerify
                    $this->processCertificateVerify($message['body']);
                    $this->handshakeTranscript .= $message['raw'];
                    break;
                case 20: // Finished
                    $this->verifyServerFinished($message['body']);
                    $this->handshakeTranscript .= $message['raw'];
                    $this->deriveApplicationSecrets();
                    break 2;
                default:
                    throw new TlsException('Unexpected handshake message: ' . $message['type'] . '.');
            }
        }

        $this->sendClientFinished();
        $this->switchToApplicationKeys();
        $this->log('Handshake TLS 1.3 completado (alpn=' . ($this->negotiatedProtocol ?: 'ninguno') . ')');
    }

    public function writeApplicationData(string $data): void
    {
        if ($this->writeKey === '') {
            throw new TlsException('The handshake has not completed yet.');
        }
        foreach (str_split($data, 16384) as $chunk) {
            $this->writeEncryptedRecord(23, $chunk);
        }
    }

    public function readApplicationData(): string
    {
        while (true) {
            if ($this->closed) {
                return '';
            }
            $record = $this->readRecord();
            if ($record['type'] === 23) {
                return $record['payload'];
            }
            if ($record['type'] === 22) {
                // Post-handshake NewSessionTicket / KeyUpdate.
                $this->handlePostHandshake($record['payload']);
                continue;
            }
            if ($record['type'] === 21) {
                $this->closed = true;
                if (strlen($record['payload']) > 1 && ord($record['payload'][1]) === 0) {
                    return '';
                }
                $this->throwAlert($record['payload']);
            }
        }
    }

    private function handlePostHandshake(string $data): void
    {
        $this->postHandshakeBuffer .= $data;
        while (strlen($this->postHandshakeBuffer) >= 4) {
            $length = self::u24Value($this->postHandshakeBuffer, 1);
            if (strlen($this->postHandshakeBuffer) < 4 + $length) {
                return;
            }
            $type = ord($this->postHandshakeBuffer[0]);
            $body = substr($this->postHandshakeBuffer, 4, $length);
            $this->postHandshakeBuffer = substr($this->postHandshakeBuffer, 4 + $length);

            if ($type === 24) {
                $this->handleKeyUpdate($body);
            }
        }
    }

    private function handleKeyUpdate(string $body): void
    {
        $requested = strlen($body) > 0 && ord($body[0]) === 1;

        // The server's KeyUpdate is encrypted with the old keys.
        $this->serverAppSecret = $this->hkdfExpandLabel(
            $this->serverAppSecret,
            'traffic upd',
            '',
            $this->hashLength
        );
        $this->readKey = $this->hkdfExpandLabel($this->serverAppSecret, 'key', '', $this->keyLength);
        $this->readIv = $this->hkdfExpandLabel($this->serverAppSecret, 'iv', '', 12);
        $this->readSequence = 0;

        if ($requested) {
            $this->writeEncryptedRecord(22, "\x18" . self::u24(1) . "\x00");
            $this->clientAppSecret = $this->hkdfExpandLabel(
                $this->clientAppSecret,
                'traffic upd',
                '',
                $this->hashLength
            );
            $this->writeKey = $this->hkdfExpandLabel($this->clientAppSecret, 'key', '', $this->keyLength);
            $this->writeIv = $this->hkdfExpandLabel($this->clientAppSecret, 'iv', '', 12);
            $this->writeSequence = 0;
        }

        $this->log('KeyUpdate TLS aplicado');
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }

    public function close(): void
    {
        if (is_resource($this->socket)) {
            @fclose($this->socket);
        }
        $this->socket = null;
        $this->closed = true;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function openTransport(): void
    {
        $target = str_contains($this->host, ':') && !str_starts_with($this->host, '[')
            ? '[' . $this->host . ']'
            : $this->host;
        $errno = 0;
        $error = '';
        $socket = @stream_socket_client(
            'tcp://' . $target . ':' . $this->port,
            $errno,
            $error,
            $this->timeout,
            STREAM_CLIENT_CONNECT
        );
        if ($socket === false) {
            throw new TlsException(sprintf(
                'Could not connect to %s:%d: %s',
                $this->host,
                $this->port,
                $error !== '' ? $error : 'error ' . $errno
            ));
        }
        $this->socket = $socket;
        $seconds = (int) floor($this->timeout);
        stream_set_timeout($this->socket, $seconds, (int) round(($this->timeout - $seconds) * 1000000));
    }

    private function buildClientHello(): string
    {
        $grease = self::greaseValue();
        $extensions = '';

        $extensions .= self::extension($grease, '');

        if (!filter_var($this->host, FILTER_VALIDATE_IP)) {
            $serverName = "\x00" . self::u16(strlen($this->host)) . $this->host;
            $extensions .= self::extension(0x0000, self::u16(strlen($serverName)) . $serverName);
        }

        $extensions .= self::extension(0x0017, '');
        $extensions .= self::extension(0xff01, "\x00");
        // Chrome 152 also advertises X25519MLKEM768 (0x11ec); it is omitted here
        // because completing the handshake would require ML-KEM-768.
        $groups = pack('nnnn', $grease, 0x001d, 0x0017, 0x0018);
        $extensions .= self::extension(0x000a, self::u16(strlen($groups)) . $groups);
        $extensions .= self::extension(0x000b, "\x01\x00");
        $extensions .= self::extension(0x0023, '');
        $alpn = self::alpnList($this->alpn);
        $extensions .= self::extension(0x0010, self::u16(strlen($alpn)) . $alpn);
        $extensions .= self::extension(0x0005, "\x01\x00\x00\x00\x00");
        $signatureAlgorithms = pack(
            'nnnnnnnnnnn',
            0x0403,
            0x0804,
            0x0401,
            0x0503,
            0x0805,
            0x0501,
            0x0806,
            0x0603,
            0x0203,
            0x0201,
            $grease
        );
        $extensions .= self::extension(0x000d, self::u16(strlen($signatureAlgorithms)) . $signatureAlgorithms);
        $extensions .= self::extension(0x0012, '');

        $keyShares = self::u16($grease) . self::u16(1) . "\x00"
            . self::u16(0x001d) . self::u16(32) . $this->x25519Public;
        $extensions .= self::extension(0x0033, self::u16(strlen($keyShares)) . $keyShares);
        $extensions .= self::extension(0x002d, "\x01\x01");
        $versions = pack('nnn', $grease, 0x0304, 0x0303);
        $extensions .= self::extension(0x002b, chr(strlen($versions)) . $versions);
        $extensions .= self::extension(0x001b, "\x02\x00\x01");

        // ALPS: only the list of protocols that carry settings.
        $alpsProtocols = chr(2) . 'h2';
        $extensions .= self::extension(0x44cd, self::u16(strlen($alpsProtocols)) . $alpsProtocols);


        $cipherSuites = pack(
            'nnnnnnnnnnnnnnnn',
            $grease,
            0x1301,
            0x1302,
            0x1303,
            0xc02b,
            0xc02f,
            0xc02c,
            0xc030,
            0xcca9,
            0xcca8,
            0xc013,
            0xc014,
            0x009c,
            0x009d,
            0x002f,
            0x0035
        );

        $random = pack('N', time()) . random_bytes(28);
        $sessionId = random_bytes(32);

        $buildBody = function (string $extensionBytes) use ($random, $sessionId, $cipherSuites): string {
            return "\x03\x03"
                . $random
                . chr(strlen($sessionId)) . $sessionId
                . self::u16(strlen($cipherSuites)) . $cipherSuites
                . "\x01\x00"
                . self::u16(strlen($extensionBytes)) . $extensionBytes;
        };

        $body = $buildBody($extensions);
        if (4 + strlen($body) < 512) {
            $padding = 512 - 4 - strlen($body) - 4;
            if ($padding > 0) {
                $body = $buildBody($extensions . self::extension(0x0015, str_repeat("\x00", $padding)));
            }
        }

        return "\x01" . self::u24(strlen($body)) . $body;
    }

    /**
     * @param list<string> $protocols
     */
    private static function alpnList(array $protocols): string
    {
        $out = '';
        foreach ($protocols as $protocol) {
            $out .= chr(strlen($protocol)) . $protocol;
        }
        return $out;
    }

    private function processServerHello(string $body): void
    {
        $offset = 34;
        $sessionIdLength = ord($body[$offset]);
        $offset += 1 + $sessionIdLength;
        $cipherSuite = unpack('n', substr($body, $offset, 2))[1];
        $offset += 2;
        $offset += 1; // compression
        $extensionsLength = unpack('n', substr($body, $offset, 2))[1];
        $offset += 2;
        $extensions = self::parseExtensions(substr($body, $offset, $extensionsLength));

        if (!isset($extensions[0x002b]) || substr($extensions[0x002b], 0, 2) !== "\x03\x04") {
            throw new TlsException('The server did not negotiate TLS 1.3.');
        }

        [$this->cipher, $this->hashAlgo, $this->keyLength] = match ($cipherSuite) {
            0x1301 => ['aes-128-gcm', 'sha256', 16],
            0x1302 => ['aes-256-gcm', 'sha384', 32],
            0x1303 => ['chacha20-poly1305', 'sha256', 32],
            default => throw new TlsException(sprintf('Unsupported TLS 1.3 cipher suite: 0x%04x.', $cipherSuite)),
        };
        $this->hashLength = $this->hashAlgo === 'sha384' ? 48 : 32;

        if (!isset($extensions[0x0033])) {
            throw new TlsException('ServerHello without key_share.');
        }
        $keyShare = $extensions[0x0033];
        $group = unpack('n', substr($keyShare, 0, 2))[1];
        $keyLength = unpack('n', substr($keyShare, 2, 2))[1];
        if ($group !== 0x001d || $keyLength !== 32) {
            throw new TlsException(sprintf('Unexpected key share (group 0x%04x, %d bytes).', $group, $keyLength));
        }

        $sharedSecret = self::x25519SharedSecret(substr($keyShare, 4, 32), $this->x25519Key);

        $zeros = str_repeat("\x00", $this->hashLength);
        $earlySecret = $this->hkdfExtract($zeros, $zeros);
        $derived = $this->hkdfExpandLabel($earlySecret, 'derived', $this->emptyHash(), $this->hashLength);
        $handshakeSecret = $this->hkdfExtract($derived, $sharedSecret);
        $this->masterSecretSeed = $this->hkdfExpandLabel(
            $handshakeSecret,
            'derived',
            $this->emptyHash(),
            $this->hashLength
        );

        $transcriptHash = hash($this->hashAlgo, $this->handshakeTranscript, true);
        $this->clientHandshakeSecret = $this->hkdfExpandLabel(
            $handshakeSecret,
            'c hs traffic',
            $transcriptHash,
            $this->hashLength
        );
        $this->serverHandshakeSecret = $this->hkdfExpandLabel(
            $handshakeSecret,
            's hs traffic',
            $transcriptHash,
            $this->hashLength
        );

        $this->readKey = $this->hkdfExpandLabel($this->serverHandshakeSecret, 'key', '', $this->keyLength);
        $this->readIv = $this->hkdfExpandLabel($this->serverHandshakeSecret, 'iv', '', 12);
        $this->readSequence = 0;
        $this->writeKey = $this->hkdfExpandLabel($this->clientHandshakeSecret, 'key', '', $this->keyLength);
        $this->writeIv = $this->hkdfExpandLabel($this->clientHandshakeSecret, 'iv', '', 12);
        $this->writeSequence = 0;
    }

    private function emptyHash(): string
    {
        return hash($this->hashAlgo, '', true);
    }

    private function hkdfExtract(string $salt, string $ikm): string
    {
        return hash_hmac($this->hashAlgo, $ikm, $salt, true);
    }

    private function hkdfExpandLabel(string $secret, string $label, string $context, int $length): string
    {
        $fullLabel = 'tls13 ' . $label;
        $info = self::u16($length) . chr(strlen($fullLabel)) . $fullLabel . chr(strlen($context)) . $context;

        $output = '';
        $previous = '';
        for ($counter = 1; strlen($output) < $length; $counter++) {
            $previous = hash_hmac($this->hashAlgo, $previous . $info . chr($counter), $secret, true);
            $output .= $previous;
        }

        return substr($output, 0, $length);
    }

    private function deriveSecret(string $secret, string $label): string
    {
        return $this->hkdfExpandLabel(
            $secret,
            $label,
            hash($this->hashAlgo, $this->handshakeTranscript, true),
            $this->hashLength
        );
    }

    private function processEncryptedExtensions(string $body): void
    {
        $extensionsLength = unpack('n', substr($body, 0, 2))[1];
        $extensions = self::parseExtensions(substr($body, 2, $extensionsLength));

        if (isset($extensions[0x0010])) {
            $data = $extensions[0x0010];
            $listLength = unpack('n', substr($data, 0, 2))[1];
            $offset = 2;
            $end = 2 + $listLength;
            $protocols = [];
            while ($offset < $end) {
                $length = ord($data[$offset]);
                $offset++;
                $protocols[] = substr($data, $offset, $length);
                $offset += $length;
            }
            $this->negotiatedProtocol = $protocols[0] ?? '';
        }
    }

    private function processCompressedCertificate(string $body): void
    {
        $algorithm = unpack('n', substr($body, 0, 2))[1];
        $uncompressedLength = (ord($body[2]) << 16) | (ord($body[3]) << 8) | ord($body[4]);

        if ($algorithm !== 1) {
            throw new TlsException('Unsupported certificate compression: ' . $algorithm . '.');
        }
        $compressedLength = self::u24Value($body, 5);
        $compressed = substr($body, 8, $compressedLength);
        $certificate = @zlib_decode($compressed);
        if ($certificate === false) {
            $certificate = @gzuncompress($compressed);
        }
        if ($certificate === false) {
            $certificate = @gzinflate($compressed);
        }
        if ($certificate === false || strlen($certificate) !== $uncompressedLength) {
            throw new TlsException(sprintf(
                'Could not decompress the certificate (alg %d, %d compressed bytes, %d expected).',
                $algorithm,
                strlen($compressed),
                $uncompressedLength
            ));
        }

        $this->processCertificate($certificate);
    }

    private function processCertificate(string $body): void
    {
        $contextLength = ord($body[0]);
        $offset = 1 + $contextLength;
        $listLength = self::u24Value($body, $offset);
        $offset += 3;
        $end = $offset + $listLength;

        $chain = [];
        while ($offset < $end) {
            $certificateLength = self::u24Value($body, $offset);
            $offset += 3;
            $chain[] = substr($body, $offset, $certificateLength);
            $offset += $certificateLength;
            $extensionsLength = unpack('n', substr($body, $offset, 2))[1];
            $offset += 2 + $extensionsLength;
        }

        if ($chain === []) {
            throw new TlsException('The server did not send a certificate.');
        }

        $this->leafCertificatePem = self::derToPem($chain[0], 'CERTIFICATE');
        $this->peerCertificate = openssl_x509_parse($this->leafCertificatePem) ?: [];

        if (!$this->verifyPeer) {
            return;
        }
        if ($this->caFile === null) {
            throw new TlsException('No system CA bundle was found.');
        }

        $untrustedFile = null;
        try {
            if (count($chain) > 1) {
                $pem = '';
                foreach (array_slice($chain, 1) as $der) {
                    $pem .= self::derToPem($der, 'CERTIFICATE');
                }
                $created = tempnam(sys_get_temp_dir(), 'tls13-ca-');
                if ($created === false) {
                    throw new TlsException('Could not create a temporary file for the certificate chain.');
                }
                $untrustedFile = $created;
                file_put_contents($untrustedFile, $pem);
            }

            $valid = openssl_x509_checkpurpose(
                $this->leafCertificatePem,
                X509_PURPOSE_SSL_SERVER,
                [$this->caFile],
                $untrustedFile
            );
            if (!$valid) {
                throw new TlsException('The server certificate is not valid for ' . $this->verifyHost . '.');
            }
            $this->assertHostnameMatches($this->verifyHost);
        } finally {
            if ($untrustedFile !== null) {
                @unlink($untrustedFile);
            }
        }
    }

    private function assertHostnameMatches(string $host): void
    {
        $san = $this->peerCertificate['extensions']['subjectAltName'] ?? '';
        $names = [];
        if (is_string($san) && $san !== '') {
            foreach (explode(',', $san) as $entry) {
                $entry = trim($entry);
                if (stripos($entry, 'DNS:') === 0) {
                    $names[] = substr($entry, 4);
                } elseif (stripos($entry, 'IP Address:') === 0) {
                    $names[] = substr($entry, 11);
                }
            }
        }
        if ($names === [] && isset($this->peerCertificate['subject']['CN'])) {
            $names[] = (string) $this->peerCertificate['subject']['CN'];
        }
        if ($names === []) {
            throw new TlsException('The certificate does not declare any server name.');
        }

        $host = strtolower(rtrim($host, '.'));
        $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
        foreach ($names as $name) {
            $candidate = strtolower(rtrim(trim($name), '.'));
            if ($isIp ? $candidate === $host : self::hostMatchesPattern($host, $candidate)) {
                return;
            }
        }

        throw new TlsException('The certificate does not match ' . $host . '.');
    }

    private static function hostMatchesPattern(string $host, string $pattern): bool
    {
        if ($pattern === $host) {
            return true;
        }
        if (str_starts_with($pattern, '*.')) {
            $suffix = substr($pattern, 1);
            if (str_ends_with($host, $suffix)) {
                $label = substr($host, 0, -strlen($suffix));
                return $label !== '' && !str_contains($label, '.');
            }
        }

        return false;
    }

    private function processCertificateVerify(string $body): void
    {
        $signatureScheme = unpack('n', substr($body, 0, 2))[1];
        $signatureLength = unpack('n', substr($body, 2, 2))[1];
        $signature = substr($body, 4, $signatureLength);

        $content = str_repeat(' ', 64)
            . "TLS 1.3, server CertificateVerify\x00"
            . hash($this->hashAlgo, $this->handshakeTranscript, true);

        $publicKey = openssl_pkey_get_public($this->leafCertificatePem);
        if ($publicKey === false) {
            throw new TlsException('Could not read the public key from the certificate.');
        }

        $verified = match ($signatureScheme) {
            0x0403, 0x0804 => $this->verifySignature($content, $signature, $publicKey, 'sha256', $signatureScheme),
            0x0503, 0x0805 => $this->verifySignature($content, $signature, $publicKey, 'sha384', $signatureScheme),
            0x0603, 0x0806 => $this->verifySignature($content, $signature, $publicKey, 'sha512', $signatureScheme),
            0x0401 => openssl_verify($content, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1,
            0x0501 => openssl_verify($content, $signature, $publicKey, OPENSSL_ALGO_SHA384) === 1,
            0x0601 => openssl_verify($content, $signature, $publicKey, OPENSSL_ALGO_SHA512) === 1,
            default => throw new TlsException(sprintf(
                'Unsupported signature algorithm: 0x%04x.',
                $signatureScheme
            )),
        };

        if (!$verified) {
            throw new TlsException('The CertificateVerify signature is not valid.');
        }
    }

    /**
     * @param \OpenSSLAsymmetricKey|resource $publicKey
     */
    private function verifySignature(
        string $content,
        string $signature,
        $publicKey,
        string $hashAlgo,
        int $signatureScheme
    ): bool {
        $isRsaPss = in_array($signatureScheme, [0x0804, 0x0805, 0x0806], true);
        if (!$isRsaPss) {
            $algorithm = match ($hashAlgo) {
                'sha384' => OPENSSL_ALGO_SHA384,
                'sha512' => OPENSSL_ALGO_SHA512,
                default => OPENSSL_ALGO_SHA256,
            };
            return openssl_verify($content, $signature, $publicKey, $algorithm) === 1;
        }

        $details = openssl_pkey_get_details($publicKey);
        if (!isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new TlsException('RSA-PSS CertificateVerify with a non-RSA key.');
        }

        return self::verifyRsaPss(
            $content,
            $signature,
            $details['rsa']['n'],
            $details['rsa']['e'],
            $hashAlgo,
            strlen(hash($hashAlgo, '', true))
        );
    }

    private function verifyServerFinished(string $body): void
    {
        $finishedKey = $this->hkdfExpandLabel(
            $this->serverHandshakeSecret,
            'finished',
            '',
            $this->hashLength
        );
        $expected = hash_hmac(
            $this->hashAlgo,
            hash($this->hashAlgo, $this->handshakeTranscript, true),
            $finishedKey,
            true
        );

        if (!hash_equals($expected, $body)) {
            throw new TlsException('The server Finished does not match.');
        }
    }

    private function deriveApplicationSecrets(): void
    {
        $zeros = str_repeat("\x00", $this->hashLength);
        $masterSecret = $this->hkdfExtract($this->masterSecretSeed, $zeros);
        $this->clientAppSecret = $this->deriveSecret($masterSecret, 'c ap traffic');
        $this->serverAppSecret = $this->deriveSecret($masterSecret, 's ap traffic');
    }

    private function sendClientFinished(): void
    {
        $finishedKey = $this->hkdfExpandLabel(
            $this->clientHandshakeSecret,
            'finished',
            '',
            $this->hashLength
        );
        $verifyData = hash_hmac(
            $this->hashAlgo,
            hash($this->hashAlgo, $this->handshakeTranscript, true),
            $finishedKey,
            true
        );

        $message = "\x14" . self::u24(strlen($verifyData)) . $verifyData;
        $this->writeEncryptedRecord(22, $message);
        $this->handshakeTranscript .= $message;
    }

    private function switchToApplicationKeys(): void
    {
        $this->readKey = $this->hkdfExpandLabel($this->serverAppSecret, 'key', '', $this->keyLength);
        $this->readIv = $this->hkdfExpandLabel($this->serverAppSecret, 'iv', '', 12);
        $this->readSequence = 0;
        $this->writeKey = $this->hkdfExpandLabel($this->clientAppSecret, 'key', '', $this->keyLength);
        $this->writeIv = $this->hkdfExpandLabel($this->clientAppSecret, 'iv', '', 12);
        $this->writeSequence = 0;
    }

    /**
     * @return array{type: int, body: string, raw: string}
     */
    private function nextHandshakeMessage(): array
    {
        while (true) {
            if (strlen($this->handshakeBuffer) >= 4) {
                $type = ord($this->handshakeBuffer[0]);
                $length = self::u24Value($this->handshakeBuffer, 1);
                if (strlen($this->handshakeBuffer) >= 4 + $length) {
                    $raw = substr($this->handshakeBuffer, 0, 4 + $length);
                    $this->handshakeBuffer = substr($this->handshakeBuffer, 4 + $length);
                    return ['type' => $type, 'body' => substr($raw, 4), 'raw' => $raw];
                }
            }

            $record = $this->readRecord();
            if ($record['type'] === 22) {
                $this->handshakeBuffer .= $record['payload'];
            } elseif ($record['type'] === 20) {
                continue;
            } elseif ($record['type'] === 21) {
                $this->throwAlert($record['payload']);
            } else {
                throw new TlsException('Unexpected record during the handshake: ' . $record['type'] . '.');
            }
        }
    }

    private function writePlainRecord(int $type, string $payload): void
    {
        $this->writeAll(chr($type) . "\x03\x01" . self::u16(strlen($payload)) . $payload);
    }

    private function writeEncryptedRecord(int $type, string $payload): void
    {
        $inner = $payload . chr($type);
        $header = chr(23) . "\x03\x03" . self::u16(strlen($inner) + 16);
        $nonce = $this->nonce($this->writeIv, $this->writeSequence++);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $inner,
            $this->cipher,
            $this->writeKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $header,
            16
        );
        if ($ciphertext === false) {
            throw new TlsException('Could not encrypt a TLS record.');
        }

        $this->writeAll($header . $ciphertext . $tag);
    }

    /**
     * @return array{type: int, payload: string}
     */
    private function readRecord(): array
    {
        $header = $this->readBytes(5);
        $type = ord($header[0]);
        $length = unpack('n', substr($header, 3, 2))[1];
        $payload = $length > 0 ? $this->readBytes($length) : '';

        if ($type !== 23 || $this->readKey === '') {
            return ['type' => $type, 'payload' => $payload];
        }

        $tag = substr($payload, -16);
        $ciphertext = substr($payload, 0, -16);
        $nonce = $this->nonce($this->readIv, $this->readSequence++);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->cipher,
            $this->readKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $header
        );
        if ($plaintext === false) {
            throw new TlsException('Could not decrypt a TLS record (bad_record_mac).');
        }

        $index = strlen($plaintext) - 1;
        while ($index >= 0 && $plaintext[$index] === "\x00") {
            $index--;
        }
        if ($index < 0) {
            throw new TlsException('Empty TLS record.');
        }

        return ['type' => ord($plaintext[$index]), 'payload' => substr($plaintext, 0, $index)];
    }

    private function nonce(string $iv, int $sequence): string
    {
        return $iv ^ str_pad(pack('N', $sequence), 12, "\x00", STR_PAD_LEFT);
    }

    private function readBytes(int $length): string
    {
        if ($length === 0) {
            return '';
        }
        $buffer = '';
        while (strlen($buffer) < $length) {
            if (!is_resource($this->socket)) {
                throw new TlsException('The TLS connection is closed.');
            }
            $chunk = fread($this->socket, $length - strlen($buffer));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->socket);
                if (!empty($meta['timed_out'])) {
                    throw new TlsException('Timed out waiting for data from the server.');
                }
                if (feof($this->socket)) {
                    $this->closed = true;
                    throw new TlsException('The server closed the connection unexpectedly.');
                }
                usleep(1000);
                continue;
            }
            $buffer .= $chunk;
        }

        return $buffer;
    }

    private function writeAll(string $data): void
    {
        if (!is_resource($this->socket)) {
            throw new TlsException('The TLS connection is closed.');
        }
        $written = 0;
        $total = strlen($data);
        while ($written < $total) {
            $result = fwrite($this->socket, substr($data, $written));
            if ($result === false || $result === 0) {
                throw new TlsException('Could not write to the TLS socket.');
            }
            $written += $result;
        }
    }

    private function throwAlert(string $payload): void
    {
        $description = strlen($payload) > 1 ? ord($payload[1]) : 0;
        $name = self::ALERTS[$description] ?? ('alerta ' . $description);
        throw new TlsException('The server sent a TLS alert: ' . $name . '.');
    }

    private function log(string $message): void
    {
        if ($this->logger !== null) {
            ($this->logger)($message);
        }
    }

    /**
     * @return array{0: string, 1: \OpenSSLAsymmetricKey|resource}
     */
    public static function generateX25519(): array
    {
        $key = false;
        if (defined('OPENSSL_KEYTYPE_X25519')) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_X25519]);
        }
        if ($key === false) {
            // PHP < 8.4 does not expose the constant, so the PKCS#8 key is built by hand (RFC 8410).
            $der = hex2bin('302e020100300506032b656e04220420') . random_bytes(32);
            $pem = "-----BEGIN PRIVATE KEY-----\n"
                . chunk_split(base64_encode($der), 64, "\n")
                . "-----END PRIVATE KEY-----\n";
            $key = openssl_pkey_get_private($pem);
        }
        if ($key === false) {
            throw new TlsException('Could not generate an X25519 key: ' . (openssl_error_string() ?: 'OpenSSL without X25519 support'));
        }
        $details = openssl_pkey_get_details($key);
        $publicDer = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $details['key']) ?? '');
        if (!is_string($publicDer) || strlen($publicDer) !== 44
            || strncmp($publicDer, hex2bin('302a300506032b656e032100'), 12) !== 0) {
            throw new TlsException('Unexpected X25519 SPKI format.');
        }

        return [substr($publicDer, 12), $key];
    }

    /**
     * @param \OpenSSLAsymmetricKey|resource $privateKey
     */
    public static function x25519SharedSecret(string $peerPublic, $privateKey): string
    {
        $der = hex2bin('302a300506032b656e032100') . $peerPublic;
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $peer = openssl_pkey_get_public($pem);
        if ($peer === false) {
            throw new TlsException('Invalid X25519 public key.');
        }

        $shared = openssl_pkey_derive($peer, $privateKey, 32);
        if (!is_string($shared) || strlen($shared) !== 32) {
            throw new TlsException('Could not compute the X25519 shared secret.');
        }
        if (trim($shared, "\x00") === '') {
            throw new TlsException('Degenerate X25519 shared secret.');
        }

        return $shared;
    }

    private static function verifyRsaPss(
        string $message,
        string $signature,
        string $modulus,
        string $exponent,
        string $hashAlgo,
        int $saltLength
    ): bool {
        $modulus = ltrim($modulus, "\x00");
        $exponent = ltrim($exponent, "\x00");
        if ($modulus === '' || $exponent === '') {
            return false;
        }

        $emBits = self::binaryBitLength($modulus) - 1;
        $emLength = intdiv($emBits + 7, 8);
        $em = self::modularExponentiationToBytes($signature, $modulus, $exponent, $emLength);
        if ($em === null || strlen($em) !== $emLength) {
            return false;
        }

        $hashLength = strlen(hash($hashAlgo, '', true));
        if ($emLength < $hashLength + $saltLength + 2) {
            return false;
        }
        if (ord($em[$emLength - 1]) !== 0xbc) {
            return false;
        }

        $dbLength = $emLength - $hashLength - 1;
        $maskedDb = substr($em, 0, $dbLength);
        $hash = substr($em, $dbLength, $hashLength);

        $unusedBits = 8 * $emLength - $emBits;
        if ($unusedBits > 0 && (ord($maskedDb[0]) & (0xff << (8 - $unusedBits)) & 0xff) !== 0) {
            return false;
        }

        $db = $maskedDb ^ self::mgf1($hash, $dbLength, $hashAlgo);
        if ($unusedBits > 0) {
            $db[0] = chr(ord($db[0]) & (0xff >> $unusedBits));
        }

        $paddingLength = $dbLength - $saltLength - 1;
        if ($paddingLength < 0
            || substr($db, 0, $paddingLength) !== str_repeat("\x00", $paddingLength)
            || ($paddingLength < strlen($db) && ord($db[$paddingLength]) !== 1)) {
            return false;
        }

        $salt = substr($db, $paddingLength + 1);
        $expected = hash($hashAlgo, str_repeat("\x00", 8) . hash($hashAlgo, $message, true) . $salt, true);

        return hash_equals($expected, $hash);
    }

    private static function mgf1(string $seed, int $length, string $hashAlgo): string
    {
        $output = '';
        for ($counter = 0; strlen($output) < $length; $counter++) {
            $output .= hash($hashAlgo, $seed . pack('N', $counter), true);
        }
        return substr($output, 0, $length);
    }

    private static function modularExponentiationToBytes(
        string $signature,
        string $modulus,
        string $exponent,
        int $emLength
    ): ?string {
        if (function_exists('gmp_powm')) {
            $modulusValue = gmp_import($modulus);
            $exponentValue = gmp_import($exponent);
            $base = gmp_import($signature);
            if (gmp_cmp($base, $modulusValue) >= 0) {
                return null;
            }
            $bytes = gmp_export(gmp_powm($base, $exponentValue, $modulusValue));

            return strlen($bytes) > $emLength ? null : str_pad($bytes, $emLength, "\x00", STR_PAD_LEFT);
        }

        if (function_exists('bcpowmod')) {
            $modulusValue = self::binaryToDecimal($modulus);
            $exponentValue = self::binaryToDecimal($exponent);
            $base = self::binaryToDecimal($signature);
            if (bccomp($base, $modulusValue) >= 0) {
                return null;
            }
            $bytes = self::decimalToBinary(bcpowmod($base, $exponentValue, $modulusValue));

            return strlen($bytes) > $emLength ? null : str_pad($bytes, $emLength, "\x00", STR_PAD_LEFT);
        }

        throw new TlsException(
            'CertificateVerify uses RSA-PSS and this PHP build has neither the gmp nor the bcmath extension.'
        );
    }

    private static function binaryBitLength(string $binary): int
    {
        $first = ord($binary[0]);
        $leading = 0;
        for ($bit = 7; $bit >= 0; $bit--) {
            if (($first >> $bit) & 1) {
                $leading = $bit + 1;
                break;
            }
        }
        return $leading + 8 * (strlen($binary) - 1);
    }

    private static function binaryToDecimal(string $binary): string
    {
        $decimal = '0';
        foreach (str_split($binary) as $char) {
            $decimal = bcadd(bcmul($decimal, '256'), (string) ord($char));
        }
        return $decimal;
    }

    private static function decimalToBinary(string $decimal): string
    {
        $bytes = '';
        while (bccomp($decimal, '0') > 0) {
            $bytes = chr((int) bcmod($decimal, '256')) . $bytes;
            $decimal = bcdiv($decimal, '256', 0);
        }
        return $bytes;
    }

    public static function derToPem(string $der, string $label): string
    {
        return '-----BEGIN ' . $label . "-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . '-----END ' . $label . "-----\n";
    }

    /**
     * @return array<int, string>
     */
    private static function parseExtensions(string $data): array
    {
        $extensions = [];
        $offset = 0;
        $length = strlen($data);
        while ($offset + 4 <= $length) {
            $type = unpack('n', substr($data, $offset, 2))[1];
            $size = unpack('n', substr($data, $offset + 2, 2))[1];
            $offset += 4;
            $extensions[$type] = substr($data, $offset, $size);
            $offset += $size;
        }
        return $extensions;
    }

    private static function greaseValue(): int
    {
        return 0x0a0a + 0x1010 * random_int(0, 15);
    }

    private static function extension(int $type, string $data): string
    {
        return self::u16($type) . self::u16(strlen($data)) . $data;
    }

    private static function u16(int $value): string
    {
        return pack('n', $value);
    }

    private static function u24(int $value): string
    {
        return chr(($value >> 16) & 0xff) . chr(($value >> 8) & 0xff) . chr($value & 0xff);
    }

    private static function u24Value(string $data, int $offset): int
    {
        return (ord($data[$offset]) << 16) | (ord($data[$offset + 1]) << 8) | ord($data[$offset + 2]);
    }

    private static function locateCaBundle(): ?string
    {
        $candidates = [];
        $env = getenv('SSL_CERT_FILE');
        if (is_string($env) && $env !== '') {
            $candidates[] = $env;
        }
        if (function_exists('openssl_get_cert_locations')) {
            $locations = openssl_get_cert_locations();
            if (isset($locations['default_cert_file']) && $locations['default_cert_file'] !== '') {
                $candidates[] = $locations['default_cert_file'];
            }
        }
        foreach ([
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/ca-bundle.pem',
            '/etc/ssl/cert.pem',
        ] as $candidate) {
            $candidates[] = $candidate;
        }

        foreach ($candidates as $candidate) {
            if (is_file($candidate) && is_readable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
