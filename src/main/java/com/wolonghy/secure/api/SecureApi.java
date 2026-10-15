/*
 * Copyright 2026 Beijing Wolong Huiyan Technology Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wolonghy.secure.api;

import com.wolonghy.secure.api.codec.Base64Codec;
import com.wolonghy.secure.api.compress.GzipCompressor;
import com.wolonghy.secure.api.crypto.AesGcmCipher;
import com.wolonghy.secure.api.exception.SecureApiException;

import java.nio.charset.StandardCharsets;

/**
 * Main entry point for the wolonghy-secure-api library.
 *
 * <p>Provides a high-level, one-call API for securing RESTful payloads with
 * AES-256-GCM encryption, Gzip compression, and Base64 encoding.</p>
 *
 * <h3>Encryption pipeline</h3>
 * <pre>
 *   Plaintext → AES-GCM Encrypt → Gzip Compress → Base64 Encode → Ciphertext String
 * </pre>
 *
 * <h3>Decryption pipeline</h3>
 * <pre>
 *   Ciphertext String → Base64 Decode → Gzip Decompress → AES-GCM Decrypt → Plaintext
 * </pre>
 *
 * <h3>Quick Start</h3>
 * <pre>{@code
 * String key = "12345678901234567890123456789012"; // must be 32 bytes
 *
 * // Encrypt
 * String ciphertext = SecureApi.encrypt("{\"userId\":\"123\"}", key);
 *
 * // Decrypt
 * String plaintext = SecureApi.decrypt(ciphertext, key);
 * }</pre>
 *
 * <h3>Additional variants</h3>
 * <ul>
 *   <li>{@link #encryptWithoutCompression(String, String)} /
 *       {@link #decryptWithoutCompression(String, String)} — skips Gzip compression,
 *       suitable for small or pre-compressed data.</li>
 *   <li>{@link #encryptBytes(byte[], String)} /
 *       {@link #decryptBytes(byte[], String)} — raw byte-level AES-GCM only,
 *       no compression or Base64 encoding.</li>
 * </ul>
 *
 * <p>For fine-grained control, use the individual classes in the
 * {@link com.wolonghy.secure.api.crypto}, {@link com.wolonghy.secure.api.codec},
 * and {@link com.wolonghy.secure.api.compress} packages directly.</p>
 *
 * @author Zhang Ze
 * @since 1.0.0
 * @see AesGcmCipher
 * @see GzipCompressor
 * @see Base64Codec
 * @see SecureApiException
 */
public final class SecureApi {

    private SecureApi() {
    }

    /**
     * Encrypts a plaintext string using the full pipeline:
     * AES-GCM encrypt → Gzip compress → Base64 encode.
     *
     * @param plaintext the UTF-8 plaintext string; returns {@code null} if {@code null}
     * @param secretKey the 32-byte secret key (as a UTF-8 string)
     * @return the Base64-encoded ciphertext string, or {@code null} if plaintext is {@code null}
     * @throws SecureApiException if any step in the pipeline fails
     * @throws IllegalArgumentException if secretKey is null or not 32 bytes
     */
    public static String encrypt(String plaintext, String secretKey) {
        if (plaintext == null) {
            return null;
        }
        byte[] key = toKeyBytes(secretKey);
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AesGcmCipher.encrypt(key, plainBytes);
        byte[] compressed = GzipCompressor.compress(encrypted);
        return Base64Codec.encode(compressed);
    }

    /**
     * Decrypts a ciphertext string using the full pipeline:
     * Base64 decode → Gzip decompress → AES-GCM decrypt.
     *
     * <p>Uses the default maximum decompressed size limit
     * (52428800 bytes, see {@link GzipCompressor#DEFAULT_MAX_DECOMPRESSED_SIZE}).</p>
     *
     * @param ciphertext the Base64-encoded ciphertext string; returns {@code null} if {@code null}
     * @param secretKey  the 32-byte secret key (as a UTF-8 string)
     * @return the decrypted UTF-8 plaintext string, or {@code null} if ciphertext is {@code null}
     * @throws SecureApiException if any step in the pipeline fails (including authentication failure)
     * @throws IllegalArgumentException if secretKey is null or not 32 bytes
     */
    public static String decrypt(String ciphertext, String secretKey) {
        return decrypt(ciphertext, secretKey, GzipCompressor.DEFAULT_MAX_DECOMPRESSED_SIZE);
    }

    /**
     * Decrypts a ciphertext string using the full pipeline:
     * Base64 decode → Gzip decompress → AES-GCM decrypt.
     *
     * @param ciphertext          the Base64-encoded ciphertext string; returns {@code null} if {@code null}
     * @param secretKey           the 32-byte secret key (as a UTF-8 string)
     * @param maxDecompressedSize the maximum allowed decompressed size in bytes, must be positive
     * @return the decrypted UTF-8 plaintext string, or {@code null} if ciphertext is {@code null}
     * @throws SecureApiException if any step in the pipeline fails (including authentication failure
     *                            or decompressed data exceeding the size limit)
     * @throws IllegalArgumentException if secretKey is null, not 32 bytes, or maxDecompressedSize is not positive
     */
    public static String decrypt(String ciphertext, String secretKey, int maxDecompressedSize) {
        if (ciphertext == null) {
            return null;
        }
        byte[] key = toKeyBytes(secretKey);

        byte[] decoded = Base64Codec.decode(ciphertext);
        byte[] decompressed = GzipCompressor.decompress(decoded, maxDecompressedSize);
        byte[] plainBytes = AesGcmCipher.decrypt(key, decompressed);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts a plaintext string using AES-GCM and Base64 encoding (no compression).
     *
     * <p>Use this when the data is small or already compressed, and the Gzip step
     * would add unnecessary overhead.</p>
     *
     * @param plaintext the UTF-8 plaintext string; returns {@code null} if {@code null}
     * @param secretKey the 32-byte secret key (as a UTF-8 string)
     * @return the Base64-encoded ciphertext string, or {@code null} if plaintext is {@code null}
     * @throws SecureApiException if encryption or encoding fails
     * @throws IllegalArgumentException if secretKey is null or not 32 bytes
     */
    public static String encryptWithoutCompression(String plaintext, String secretKey) {
        if (plaintext == null) {
            return null;
        }
        byte[] key = toKeyBytes(secretKey);
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = AesGcmCipher.encrypt(key, plainBytes);
        return Base64Codec.encode(encrypted);
    }

    /**
     * Decrypts a Base64-encoded ciphertext string using AES-GCM (no decompression).
     *
     * <p>Use this to decrypt data that was encrypted with
     * {@link #encryptWithoutCompression(String, String)}.</p>
     *
     * @param ciphertext the Base64-encoded ciphertext string; returns {@code null} if {@code null}
     * @param secretKey  the 32-byte secret key (as a UTF-8 string)
     * @return the decrypted UTF-8 plaintext string, or {@code null} if ciphertext is {@code null}
     * @throws SecureApiException if decryption or authentication fails
     * @throws IllegalArgumentException if secretKey is null or not 32 bytes
     */
    public static String decryptWithoutCompression(String ciphertext, String secretKey) {
        if (ciphertext == null) {
            return null;
        }
        byte[] key = toKeyBytes(secretKey);
        byte[] decoded = Base64Codec.decode(ciphertext);
        byte[] plainBytes = AesGcmCipher.decrypt(key, decoded);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts raw bytes using AES-GCM only (no compression or encoding).
     *
     * @param data      the data to encrypt; must not be null
     * @param secretKey the 32-byte secret key (as a UTF-8 string)
     * @return the encrypted bytes (IV + ciphertext)
     * @throws SecureApiException if encryption fails
     * @throws IllegalArgumentException if data or secretKey is null, or secretKey is not 32 bytes
     */
    public static byte[] encryptBytes(byte[] data, String secretKey) {
        return AesGcmCipher.encrypt(toKeyBytes(secretKey), data);
    }

    /**
     * Decrypts raw bytes using AES-GCM only (no decompression or decoding).
     *
     * @param encryptedData the encrypted bytes (IV + ciphertext); must not be null
     * @param secretKey     the 32-byte secret key (as a UTF-8 string)
     * @return the decrypted bytes
     * @throws SecureApiException if decryption, authentication, or data format validation fails
     * @throws IllegalArgumentException if encryptedData or secretKey is null, or secretKey is not 32 bytes
     */
    public static byte[] decryptBytes(byte[] encryptedData, String secretKey) {
        return AesGcmCipher.decrypt(toKeyBytes(secretKey), encryptedData);
    }

    private static byte[] toKeyBytes(String secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key must not be null");
        }
        byte[] key = secretKey.getBytes(StandardCharsets.UTF_8);
        if (key.length != AesGcmCipher.getKeyLength()) {
            throw new IllegalArgumentException(
                    "Secret key must be " + AesGcmCipher.getKeyLength() + " bytes (AES-256), but was " + key.length + " bytes");
        }
        return key;
    }
}
