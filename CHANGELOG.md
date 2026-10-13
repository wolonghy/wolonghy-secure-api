# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-13

### Added
- `SecureApi` — main entry point with one-call `encrypt` / `decrypt` methods
- `AesGcmCipher` — AES-256-GCM authenticated encryption and decryption
- `Base64Codec` — standard and URL-safe Base64 encoding and decoding
- `GzipCompressor` — Gzip compression and decompression
- `SecureApiException` — unified runtime exception for all security operations
