<?php
declare(strict_types=1);

namespace NativeHttp;

use RuntimeException;

/** HPACK header compression for HTTP/2 (RFC 7541). */
final class Hpack
{
    /** @var array<int, array{0: string, 1: string}> */
    private static array $staticTable = [];

    /** @var array<int, array{0: int, 1: int}> code => [bits, symbol] */
    private static array $huffmanTable = [];

    /** @var list<array{0: string, 1: string}> most recent entries first */
    private array $dynamicTable = [];

    private int $dynamicTableSize = 0;

    private int $maxDynamicTableSize;

    public function __construct(int $maxDynamicTableSize = 4096)
    {
        if (self::$staticTable === []) {
            $tables = require __DIR__ . '/../resources/hpack-tables.php';
            self::$staticTable = $tables['static'];
            self::$huffmanTable = $tables['huffman'];
        }
        $this->maxDynamicTableSize = $maxDynamicTableSize;
    }

    /**
     * @param list<array{0: string, 1: string}> $fields
     */
    public function encode(array $fields): string
    {
        $out = '';
        foreach ($fields as [$name, $value]) {
            $name = strtolower($name);

            $index = self::findInStatic($name, $value);
            if ($index !== null) {
                $out .= self::encodeInt($index, 7, 0x80);
                continue;
            }

            $nameIndex = self::findNameInStatic($name);
            if ($nameIndex !== null) {
                $out .= self::encodeInt($nameIndex, 4, 0x00);
            } else {
                $out .= "\x00" . self::encodeString($name);
            }
            $out .= self::encodeString($value);
        }

        return $out;
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public function decode(string $block): array
    {
        $fields = [];
        $length = strlen($block);
        $pos = 0;

        while ($pos < $length) {
            $byte = ord($block[$pos]);

            if (($byte & 0x80) !== 0) {
                $index = self::decodeInt($block, 7, $pos);
                $fields[] = $this->resolveIndex($index);
            } elseif (($byte & 0x40) !== 0) {
                $index = self::decodeInt($block, 6, $pos);
                $name = $index === 0 ? self::decodeString($block, $pos) : $this->resolveIndex($index)[0];
                $value = self::decodeString($block, $pos);
                $fields[] = [$name, $value];
                $this->addToDynamicTable($name, $value);
            } elseif (($byte & 0x20) !== 0) {
                $this->setMaxDynamicTableSize(self::decodeInt($block, 5, $pos));
            } else {
                $index = self::decodeInt($block, 4, $pos);
                $name = $index === 0 ? self::decodeString($block, $pos) : $this->resolveIndex($index)[0];
                $fields[] = [$name, self::decodeString($block, $pos)];
            }
        }

        return $fields;
    }

    public function setMaxDynamicTableSize(int $size): void
    {
        if ($size < 0) {
            throw new RuntimeException('Invalid HPACK table size.');
        }
        $this->maxDynamicTableSize = $size;
        $this->evictDynamicTable();
    }

    private function addToDynamicTable(string $name, string $value): void
    {
        array_unshift($this->dynamicTable, [$name, $value]);
        $this->dynamicTableSize += strlen($name) + strlen($value) + 32;
        $this->evictDynamicTable();
    }

    private function evictDynamicTable(): void
    {
        while ($this->dynamicTable !== [] && $this->dynamicTableSize > $this->maxDynamicTableSize) {
            [$name, $value] = array_pop($this->dynamicTable);
            $this->dynamicTableSize -= strlen($name) + strlen($value) + 32;
        }
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function resolveIndex(int $index): array
    {
        if (isset(self::$staticTable[$index])) {
            return self::$staticTable[$index];
        }
        $dynamicIndex = $index - count(self::$staticTable) - 1;
        if (!isset($this->dynamicTable[$dynamicIndex])) {
            throw new RuntimeException("HPACK index out of range: {$index}.");
        }
        return $this->dynamicTable[$dynamicIndex];
    }

    private static function findInStatic(string $name, string $value): ?int
    {
        foreach (self::$staticTable as $index => [$n, $v]) {
            if ($n === $name && $v === $value) {
                return $index;
            }
        }
        return null;
    }

    private static function findNameInStatic(string $name): ?int
    {
        foreach (self::$staticTable as $index => [$n, $v]) {
            if ($n === $name) {
                return $index;
            }
        }
        return null;
    }

    private static function encodeInt(int $value, int $prefixBits, int $firstByteBase): string
    {
        $max = (1 << $prefixBits) - 1;
        if ($value < $max) {
            return chr($firstByteBase | $value);
        }

        $out = chr($firstByteBase | $max);
        $value -= $max;
        while ($value >= 128) {
            $out .= chr(($value % 128) | 0x80);
            $value = intdiv($value, 128);
        }
        return $out . chr($value);
    }

    private static function decodeInt(string $block, int $prefixBits, int &$pos): int
    {
        $max = (1 << $prefixBits) - 1;
        $value = ord($block[$pos]) & $max;
        $pos++;
        if ($value < $max) {
            return $value;
        }

        $shift = 0;
        $length = strlen($block);
        while ($pos < $length) {
            $byte = ord($block[$pos]);
            $pos++;
            $value += ($byte & 0x7f) << $shift;
            if (($byte & 0x80) === 0) {
                return $value;
            }
            $shift += 7;
            if ($shift > 28) {
                break;
            }
        }

        throw new RuntimeException('Truncated HPACK integer.');
    }

    private static function encodeString(string $value): string
    {
        return self::encodeInt(strlen($value), 7, 0x00) . $value;
    }

    private static function decodeString(string $block, int &$pos): string
    {
        if (!isset($block[$pos])) {
            throw new RuntimeException('Truncated HPACK string.');
        }
        $huffman = (ord($block[$pos]) & 0x80) !== 0;
        $length = self::decodeInt($block, 7, $pos);
        if ($pos + $length > strlen($block)) {
            throw new RuntimeException('Truncated HPACK string.');
        }
        $raw = substr($block, $pos, $length);
        $pos += $length;

        return $huffman ? self::huffmanDecode($raw) : $raw;
    }

    private static function huffmanDecode(string $data): string
    {
        $out = '';
        $code = 0;
        $bits = 0;

        foreach (str_split($data) as $char) {
            $byte = ord($char);
            for ($i = 7; $i >= 0; $i--) {
                $code = ($code << 1) | (($byte >> $i) & 1);
                $bits++;
                if (isset(self::$huffmanTable[$code]) && self::$huffmanTable[$code][0] === $bits) {
                    $symbol = self::$huffmanTable[$code][1];
                    if ($symbol === 256) {
                        throw new RuntimeException('Unexpected EOS symbol in HPACK string.');
                    }
                    $out .= chr($symbol);
                    $code = 0;
                    $bits = 0;
                } elseif ($bits > 30) {
                    throw new RuntimeException('Invalid HPACK Huffman code.');
                }
            }
        }

        if ($bits >= 8 || ($bits > 0 && $code !== (1 << $bits) - 1)) {
            throw new RuntimeException('Invalid HPACK Huffman padding.');
        }

        return $out;
    }
}
