# wolonghy-secure-api

[![Maven Central](https://img.shields.io/maven-central/v/com.wolonghy/wolonghy-secure-api.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/com.wolonghy/wolonghy-secure-api)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://adoptium.net/)

A lightweight Java library for **AES-256-GCM encryption**, **Gzip compression**, and **Base64 encoding** of RESTful API payloads.

## Features

- **AES-256-GCM** authenticated encryption (confidentiality + integrity)
- **Gzip compression** to reduce payload size
- **Base64 encoding** for safe data transport
- **Zero external dependencies** — JDK 8+ only
- **One-call API** for the full encrypt/decrypt pipeline

## Installation

### Maven

```xml
<dependency>
    <groupId>com.wolonghy</groupId>
    <artifactId>wolonghy-secure-api</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.wolonghy:wolonghy-secure-api:1.0.0'
```

## Quick Start

```java
import com.wolonghy.secure.api.SecureApi;

public class Example {
    public static void main(String[] args) {
        String key = "12345678901234567890123456789012";

        String jsonStr = "{\"userId\":\"123\",\"name\":\"Zhang Ze\"}";
        String ciphertext = SecureApi.encrypt(jsonStr, key);
        System.out.println("Encrypted: " + ciphertext);

        String plaintext = SecureApi.decrypt(ciphertext, key);
        System.out.println("Decrypted: " + plaintext);
    }
}
```

## How It Works

### Encryption Pipeline

```
Plaintext → AES-GCM Encrypt → Gzip Compress → Base64 Encode → Ciphertext String
```

### Decryption Pipeline

```
Ciphertext String → Base64 Decode → Gzip Decompress → AES-GCM Decrypt → Plaintext
```

> AES-GCM mode provides built-in authentication (Authentication Tag), ensuring data integrity without additional signatures.

## API Reference

### SecureApi (Main Entry Point)

| Method | Description |
|--------|-------------|
| `encrypt(String plaintext, String key)` | Full pipeline: encrypt → compress → encode |
| `decrypt(String ciphertext, String key)` | Full pipeline: decode → decompress → decrypt (default 50 MB limit) |
| `decrypt(String ciphertext, String key, int maxDecompressedSize)` | Same as above, with a custom decompressed size limit |
| `encryptBytes(byte[] data, String key)` | AES-GCM only (no compression or encoding) |
| `decryptBytes(byte[] data, String key)` | AES-GCM only (no decompression or decoding) |
| `encryptWithoutCompression(String plaintext, String key)` | AES-GCM + Base64, no Gzip (for small or pre-compressed data) |
| `decryptWithoutCompression(String ciphertext, String key)` | Decrypts data from `encryptWithoutCompression` |

### Fine-grained Components

You can also use individual components directly:

```java
import com.wolonghy.secure.api.crypto.AesGcmCipher;
import com.wolonghy.secure.api.codec.Base64Codec;
import com.wolonghy.secure.api.compress.GzipCompressor;

byte[] key = AesGcmCipher.generateKey();
byte[] encrypted = AesGcmCipher.encrypt(key, data);
byte[] decrypted = AesGcmCipher.decrypt(key, encrypted);

String encoded = Base64Codec.encode(data);
byte[] decoded = Base64Codec.decode(encoded);
String urlSafe = Base64Codec.encodeUrlSafe(data);

byte[] compressed = GzipCompressor.compress(data);
byte[] decompressed = GzipCompressor.decompress(compressed);
byte[] decompressed2 = GzipCompressor.decompress(compressed, 10 * 1024 * 1024); // custom 10 MB limit
```
