# Contributing

Thanks for your interest. Before opening a pull request:

## Environment

- PHP 8.1 or newer with `openssl`, `zlib` and (recommended) `gmp`.
- Composer and PHPUnit are not required.

## Checks before submitting

```bash
# Syntax
find src examples tests -name '*.php' -print0 | xargs -0 -n1 php -l

# Tests without network
php tests/run.php --offline

# Full suite (needs internet)
php tests/run.php
```

All of them must pass. If your change affects the protocol, add the
corresponding test to `tests/run.php`.

## Style

- `declare(strict_types=1);` in every file.
- PSR-12 where possible: 4 spaces, braces on their own line for classes and
  methods.
- Type declarations for parameters and return values; docblocks only where they
  add information (array shapes).
- Comments in English, and only when they explain *why*, not *what*.

## Scope

This project implements protocols. A behaviour change in `Tls13Socket` or
`Hpack` must be justified with the relevant RFC section and backed by a test.

## Commits

- Imperative mood: `Add flow control`, `Fix padding`.
- One logical change per commit.

## License

By contributing you agree that your contribution is published under the
project's MIT license.
